package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.ssh.describe
import bayern.kickner.dirl.ssh.describeChannelError
import bayern.kickner.dirl.ssh.openSftp
import bayern.kickner.dirl.vault.Host
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveMultipart
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.header
import io.ktor.server.response.respondOutputStream
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingContext
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.jvm.javaio.toInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.FlowContent
import kotlinx.html.FormEncType
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.a
import kotlinx.html.div
import kotlinx.html.fileInput
import kotlinx.html.form
import kotlinx.html.hiddenInput
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import kotnexlib.ResultOf2
import net.schmizz.sshj.sftp.FileAttributes
import net.schmizz.sshj.sftp.FileMode
import net.schmizz.sshj.sftp.OpenMode
import net.schmizz.sshj.sftp.RemoteResourceFilter
import net.schmizz.sshj.sftp.RemoteResourceInfo
import net.schmizz.sshj.sftp.RenameFlags
import net.schmizz.sshj.sftp.SFTPClient
import java.io.InputStream
import java.net.URLEncoder
import java.util.EnumSet

/** Directories with more entries are not listed, a compromised server could otherwise send an endless listing. */
const val MAX_LIST_ENTRIES = 10_000

/**
 * Largest multipart part accepted by the upload, so the largest file. Ktor applies it to every part: files are
 * streamed, plain form fields are read into memory completely. Only allowed users can send a request here, and they
 * can seal the vault anyway, so an oversized form field is no attack worth defending against.
 */
private const val MAX_UPLOAD_BYTES = 4L * 1024 * 1024 * 1024

/**
 * SFTP file manager.
 *
 * - `GET /hosts/{id}/files?path=` lists a directory, default is the login user's home.
 * - `GET /hosts/{id}/files/download?path=` streams a file.
 * - `POST /hosts/{id}/files/upload?path=` uploads files (multipart) into a directory, with progress in the browser.
 *   Existing files are only replaced when "Overwrite existing files" is ticked.
 * - `POST /hosts/{id}/files/mkdir`, `POST /hosts/{id}/files/delete` create directories and delete entries.
 * - `GET /hosts/{id}/files/rename?path=`, `POST /hosts/{id}/files/rename` rename or move an entry.
 *
 * Contents are moved as bytes, nothing guesses encodings. There is no editor in the browser, files are changed in the
 * terminal. Uploads write to a temporary file next to the target and rename it, so a broken transfer never leaves a
 * half-written file behind.
 */
fun Route.fileRoutes(dirl: Dirl) {
    get("/hosts/{id}/files") {
        val (_, host) = hostOr404(dirl) ?: return@get
        if (host.jumpOnly) return@get call.jumpOnlyPage(host)
        val requested = call.request.queryParameters["path"]
        val listing = withSftp(dirl, host) { sftp ->
            val dir = sftp.canonicalize(requested?.trim()?.ifBlank { null } ?: ".")
            dir to listEntries(sftp, dir).sortedWith(compareBy({ it.isDirectory.not() }, { it.name.lowercase() }))
        } ?: return@get
        val (dir, entries) = listing

        call.page("${host.name} files", call.session, Nav.HOSTS) {
            pageHeader("Files on ${host.name}") {
                linkButton("/hosts/${host.id}/terminal", "Terminal")
                linkButton("/hosts/${host.id}", "Details", "ghost")
            }
            div("stack") {
                card {
                    div("card-header") {
                        breadcrumbs(host, dir)
                        form(action = "/hosts/${host.id}/files", method = FormMethod.get, classes = "btn-row path-form") {
                            input(type = InputType.text, name = "path") {
                                value = dir
                                attributes["aria-label"] = "Path"
                                attributes["spellcheck"] = "false"
                            }
                            submit("Go", "sm")
                        }
                    }
                    div("table-wrap") {
                        table {
                            thead { tr { th { +"Name" }; th(classes = "num") { +"Size" }; th(classes = "hide-sm") { +"Modified" }; th { } } }
                            tbody {
                                if (dir != "/") tr {
                                    td("mono") { a(href = filesUrl(host, parentOf(dir))) { +"../" } }
                                    td { }
                                    td(classes = "hide-sm") { }
                                    td { }
                                }
                                entries.forEach { entry ->
                                    val isDir = entry.isDirectory
                                    tr {
                                        td("mono") {
                                            if (isDir) a(href = filesUrl(host, entry.path)) { +"${entry.name}/" }
                                            else a(href = "/hosts/${host.id}/files/download?path=${enc(entry.path)}") { +entry.name }
                                            if (entry.isLink) span("muted") { attributes["title"] = "Symbolic link"; +" →" }
                                        }
                                        td("num") { if (isDir.not()) +humanSize(entry.size) }
                                        td("nowrap hide-sm muted") { +formatTimestamp(entry.mtime * 1000) }
                                        td("actions") {
                                            linkButton("/hosts/${host.id}/files/rename?path=${enc(entry.path)}", "Rename", "sm ghost")
                                            postButton(
                                                "/hosts/${host.id}/files/delete", "Delete", "sm danger",
                                                confirm = "Delete ${entry.name}${if (isDir) " (only if empty)" else ""}?",
                                                hidden = mapOf("path" to entry.path, "dir" to dir),
                                            )
                                        }
                                    }
                                }
                                if (entries.isEmpty()) tr { td("muted") { +"Empty directory" } }
                            }
                        }
                    }
                }
                div("columns") {
                    card("Upload") {
                        form(action = "/hosts/${host.id}/files/upload?path=${enc(dir)}", method = FormMethod.post, encType = FormEncType.multipartFormData, classes = "form") {
                            attributes["data-upload"] = ""
                            // Must come before the file input: the server reads the multipart body in form order.
                            checkField("Overwrite existing files", "overwrite", false)
                            label("field") {
                                span { +"Files for $dir" }
                                fileInput(name = "file") { multiple = true; required = true }
                            }
                            div("progress") { span { } }
                            div("btn-row") { submit("Upload") }
                        }
                    }
                    card("New directory") {
                        form(action = "/hosts/${host.id}/files/mkdir", method = FormMethod.post, classes = "form") {
                            hiddenInput(name = "dir") { value = dir }
                            textField("Name", "name", "")
                            div("btn-row") { submit("Create", "") }
                        }
                    }
                }
            }
        }
    }

    get("/hosts/{id}/files/download") {
        val (_, host) = hostOr404(dirl) ?: return@get
        val path = call.request.queryParameters["path"].orEmpty()
        val client = connectedClient(dirl, host) ?: return@get
        val sftp = withContext(Dispatchers.IO) { runCatching { client.openSftp() } }.getOrElse {
            return@get call.fileError(host, describeChannelError(it))
        }
        val remote = withContext(Dispatchers.IO) { runCatching { sftp.open(path, EnumSet.of(OpenMode.READ)) } }.getOrElse {
            sftp.close()
            return@get call.fileError(host, it.message ?: "Cannot open $path")
        }
        dirl.audit.record(call.session.actor, AuditAction.SFTP_DOWNLOAD, host.name, path)
        call.response.header(
            HttpHeaders.ContentDisposition,
            ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, headerSafeFileName(path.substringAfterLast('/'))).toString(),
        )
        call.respondOutputStream(ContentType.Application.OctetStream) {
            try {
                // 16 reads of 32 KiB in flight instead of one 8 KiB read per round trip, like the upload's 16 writes.
                remote.ReadAheadRemoteFileInputStream(16).use { it.copyTo(this, 32 * 1024) }
            } finally {
                runCatching { remote.close() }
                runCatching { sftp.close() }
            }
        }
    }

    post("/hosts/{id}/files/upload") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val dir = call.request.queryParameters["path"].orEmpty()
        val client = connectedClient(dirl, host) ?: return@post
        val uploaded = mutableListOf<String>()
        val failed = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        // The checkbox is placed before the file input, so it arrives before the files in the multipart body.
        var overwrite = false

        val channel = withContext(Dispatchers.IO) { runCatching { client.openSftp() } }
        channel.getOrElse { return@post call.fileError(host, describeChannelError(it)) }.use { sftp ->
            call.receiveMultipart(formFieldLimit = MAX_UPLOAD_BYTES).forEachPart { part ->
                if (part is PartData.FormItem && part.name == "overwrite") overwrite = part.value == "on"
                if (part is PartData.FileItem) {
                    val name = safeFileName(part.originalFileName)
                    val target = "${dir.trimEnd('/')}/$name"
                    val exists = name != null && withContext(Dispatchers.IO) { runCatching { sftp.statExistence(target) != null }.getOrDefault(false) }
                    when {
                        name == null -> failed += (part.originalFileName ?: "unnamed")
                        exists && overwrite.not() -> skipped += name
                        else -> {
                            val ok = withContext(Dispatchers.IO) {
                                runCatching { part.provider().toInputStream().use { writeAtomically(sftp, target, it) } }.isSuccess
                            }
                            if (ok) uploaded += target else failed += name
                        }
                    }
                }
                part.release()
            }
        }
        uploaded.forEach { dirl.audit.record(call.session.actor, AuditAction.SFTP_UPLOAD, host.name, it) }
        if (failed.isEmpty() && skipped.isEmpty()) return@post call.respondRedirect(filesUrl(host, dir) + "&done=uploaded")
        val message = listOfNotNull(
            failed.takeIf { it.isNotEmpty() }?.let { "Failed: ${it.joinToString()}." },
            skipped.takeIf { it.isNotEmpty() }?.let { "Already exist, not overwritten: ${it.joinToString()}. Tick \"Overwrite existing files\" to replace them." },
            uploaded.takeIf { it.isNotEmpty() }?.let { "Uploaded: ${it.size} file(s)." },
        ).joinToString(" ")
        call.fileError(host, message)
    }

    post("/hosts/{id}/files/mkdir") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val dir = form["dir"].orEmpty()
        val name = safeFileName(form["name"]) ?: return@post call.respondRedirect(filesUrl(host, dir))
        val path = "${dir.trimEnd('/')}/$name"
        withSftp(dirl, host) { it.mkdir(path) } ?: return@post
        dirl.audit.record(call.session.actor, AuditAction.SFTP_MKDIR, host.name, path)
        call.respondRedirect(filesUrl(host, dir) + "&done=created")
    }

    post("/hosts/{id}/files/delete") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val path = form["path"].orEmpty()
        withSftp(dirl, host) { sftp -> deleteEntry(sftp, path) } ?: return@post
        dirl.audit.record(call.session.actor, AuditAction.SFTP_DELETE, host.name, path)
        call.respondRedirect(filesUrl(host, form["dir"].orEmpty()) + "&done=deleted")
    }

    get("/hosts/{id}/files/rename") {
        val (_, host) = hostOr404(dirl) ?: return@get
        val path = call.request.queryParameters["path"].orEmpty()
        call.page("Rename", call.session, Nav.HOSTS) {
            pageHeader("Rename or move", "on ${host.name}")
            card {
                form(action = "/hosts/${host.id}/files/rename", method = FormMethod.post, classes = "form") {
                    hiddenInput(name = "path") { value = path }
                    textField("New path", "target", path, hint = "A different directory moves the entry. Existing targets are not overwritten.")
                    div("btn-row") {
                        submit("Rename")
                        linkButton(filesUrl(host, parentOf(path)), "Cancel", "ghost")
                    }
                }
            }
        }
    }

    post("/hosts/{id}/files/rename") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val path = form["path"].orEmpty()
        val target = form["target"].orEmpty().trim()
        if (target.isEmpty() || target == path) return@post call.respondRedirect(filesUrl(host, parentOf(path)))
        withSftp(dirl, host) { it.rename(path, target) } ?: return@post
        dirl.audit.record(call.session.actor, AuditAction.SFTP_RENAME, host.name, "$path to $target")
        call.respondRedirect(filesUrl(host, parentOf(target)) + "&done=renamed")
    }
}

/**
 * Runs [block] with a fresh SFTP channel on the host's connection. Errors are rendered as an error page.
 *
 * @return the block's result, or `null` after an error page was sent.
 */
private suspend fun <T : Any> RoutingContext.withSftp(dirl: Dirl, host: Host, block: (SFTPClient) -> T): T? {
    val client = connectedClient(dirl, host) ?: return null
    return withContext(Dispatchers.IO) { runCatching { client.openSftp().use(block) } }
        .getOrElse { error -> call.fileError(host, describeChannelError(error)); null }
}

/** The host's live connection, or `null` after an error page was sent. */
private suspend fun RoutingContext.connectedClient(dirl: Dirl, host: Host) = when (val c = dirl.connections.connection(host.id)) {
    is ResultOf2.Success -> c.value
    is ResultOf2.Failure -> {
        call.fileError(host, "${host.name} is not connected: ${describe(c.value)}")
        null
    }
}

private suspend fun ApplicationCall.fileError(host: Host, message: String) =
    page("File operation failed", session, Nav.HOSTS, status = HttpStatusCode.BadGateway) {
        pageHeader("File operation failed", "on ${host.name}")
        notice("error", message)
        div("btn-row") {
            linkButton("/hosts/${host.id}/files", "Back to files")
            linkButton("/hosts/${host.id}", "Host details", "ghost")
        }
    }

/** Clickable path segments, e.g. `/ home / ada`. */
private fun FlowContent.breadcrumbs(host: Host, dir: String) = div("crumbs") {
    a(href = filesUrl(host, "/")) { +"/" }
    var current = ""
    dir.split('/').filter { it.isNotEmpty() }.forEachIndexed { i, segment ->
        current += "/$segment"
        if (i > 0) span("sep") { +"/" }
        a(href = filesUrl(host, current)) { +segment }
    }
}

/**
 * Lists [dir], at most [max] entries. sshj collects the whole listing in memory, so the filter aborts the read once
 * the limit is passed instead of letting a hostile server fill the heap.
 *
 * @throws IllegalStateException with a message for the user if the directory has more than [max] entries.
 */
fun listDirectory(sftp: SFTPClient, dir: String, max: Int = MAX_LIST_ENTRIES): List<RemoteResourceInfo> {
    var count = 0
    return sftp.ls(dir, RemoteResourceFilter {
        count++
        check(count <= max) { "This directory has more than $max entries. Dirl does not list it, use the terminal instead." }
        true
    })
}

/**
 * One row of the file listing.
 *
 * @property name File name.
 * @property path Absolute path.
 * @property type Type of the entry, for a symlink the type of its target. A broken link stays [FileMode.Type.SYMLINK].
 * @property size Size in bytes, for a symlink the size of its target.
 * @property mtime Modification time in Unix seconds.
 * @property isLink True if the entry is a symlink.
 */
data class ListedEntry(val name: String, val path: String, val type: FileMode.Type, val size: Long, val mtime: Long, val isLink: Boolean) {
    /** True for directories and links to directories. */
    val isDirectory: Boolean get() = type == FileMode.Type.DIRECTORY
}

/**
 * Lists [dir] like [listDirectory] as rows for the file manager. The server reports symlinks as such, so links to
 * directories would show up as files. Each link costs one more request to learn the type of its target.
 */
fun listEntries(sftp: SFTPClient, dir: String, max: Int = MAX_LIST_ENTRIES): List<ListedEntry> = listDirectory(sftp, dir, max).map { info ->
    val own = info.attributes
    val isLink = own.type == FileMode.Type.SYMLINK
    val target = if (isLink) runCatching { sftp.stat(info.path) }.getOrNull() else null
    ListedEntry(info.name, info.path, target?.type ?: own.type, target?.size ?: own.size, own.mtime, isLink)
}

/**
 * Deletes a file, a symlink or an empty directory. Looks at the entry itself and not at a link target, so a link is
 * always removed as link and its target is never touched.
 */
fun deleteEntry(sftp: SFTPClient, path: String) {
    val isDir = sftp.lstat(path).type == FileMode.Type.DIRECTORY
    if (isDir) runCatching { sftp.rmdir(path) }.getOrElse { error("Only empty directories can be deleted. ${it.message}") }
    else sftp.rm(path)
}

/**
 * Writes [input] to `<dir>/.<name>.dirl-tmp` and renames it over [path]. OpenSSH only supports overwriting renames
 * through its `posix-rename` extension, if the server lacks it the target is removed first.
 *
 * A symlink as [path] is resolved first, so the file it points to is written and the link stays. Writing to the
 * link path itself would replace the link with a plain file and leave the real file unchanged.
 *
 * An existing target keeps its permissions, owner and group. The temporary file is created with the target's
 * permissions, so a private key is never readable by others in between. If the SSH user may not give the file the
 * target's owner or group, the write is refused and the target stays unchanged. Changing a file of another user
 * needs a login as that user.
 *
 * A failed write removes the temporary file again, a broken upload would otherwise leave a large hidden file on a
 * possibly full file system. Once the target was removed for the fallback rename, the temporary file holds the only
 * copy of the new content and stays if that rename fails. Errors are rethrown.
 */
fun writeAtomically(sftp: SFTPClient, path: String, input: InputStream) {
    val target = resolveLink(sftp, path)
    val tmp = target.substringBeforeLast('/', ".") + "/." + target.substringAfterLast('/') + ".dirl-tmp"
    val existing = sftp.statExistence(target)
    val permissions = existing?.let { FileAttributes.Builder().withPermissions(it.mode.permissionsMask).build() }
    runCatching {
        sftp.open(tmp, EnumSet.of(OpenMode.WRITE, OpenMode.CREAT, OpenMode.TRUNC), permissions ?: FileAttributes.EMPTY).use { file ->
            file.RemoteFileOutputStream(0, 16).use { input.copyTo(it) }
        }
        if (existing != null) keepAttributes(sftp, tmp, target, existing)
    }.onFailure { error -> discardAndThrow(sftp, tmp, error) }

    if (runCatching { sftp.rename(tmp, target, setOf(RenameFlags.OVERWRITE)) }.isSuccess) return
    runCatching { if (sftp.statExistence(target) != null) sftp.rm(target) }.onFailure { error -> discardAndThrow(sftp, tmp, error) }
    sftp.rename(tmp, target)
}

/**
 * Gives [tmp] the owner, group and permissions of [original]. The owner comes first because changing it clears the
 * setuid and setgid bits, and the permissions are set again because the server's umask applies when creating.
 *
 * @throws IllegalStateException with a message for the user if the owner or group cannot be kept.
 */
private fun keepAttributes(sftp: SFTPClient, tmp: String, target: String, original: FileAttributes) {
    val created = sftp.stat(tmp)
    if (created.uid != original.uid || created.gid != original.gid) runCatching {
        sftp.setattr(tmp, FileAttributes.Builder().withUIDGID(original.uid, original.gid).build())
    }.onFailure { error ->
        throw IllegalStateException("$target belongs to another user or group (${original.uid}:${original.gid}) that this login cannot keep. Log in as its owner to change it.", error)
    }
    sftp.setattr(tmp, FileAttributes.Builder().withPermissions(original.mode.permissionsMask).build())
}

/** The real path behind a symlink, or [path] itself for everything else, including paths that do not exist yet. */
private fun resolveLink(sftp: SFTPClient, path: String): String {
    val isLink = runCatching { sftp.lstat(path).type == FileMode.Type.SYMLINK }.getOrDefault(false)
    return if (isLink) runCatching { sftp.canonicalize(path) }.getOrDefault(path) else path
}

private fun discardAndThrow(sftp: SFTPClient, tmp: String, error: Throwable): Nothing {
    runCatching { sftp.rm(tmp) }
    throw error
}

/** The last path segment of an uploaded name, or `null` for names that are empty or would leave the directory. */
fun safeFileName(raw: String?): String? {
    val name = raw?.substringAfterLast('/')?.substringAfterLast('\\')?.trim().orEmpty()
    val invalid = name.isEmpty() || name == "." || name == ".." || name.contains('\u0000')
    return if (invalid) null else name
}

/**
 * A remote file name made safe for the `Content-Disposition` header: control characters, quotes and backslashes
 * become `_`. Remote names are chosen by whoever controls the server, they must not shape response headers.
 */
fun headerSafeFileName(name: String): String =
    name.map { c -> if (c.code < 0x20 || c == '\u007f' || c == '"' || c == '\\') '_' else c }.joinToString("").ifEmpty { "download" }

/** Parent directory of an absolute path, `/` for top level entries. */
fun parentOf(path: String): String = path.trimEnd('/').substringBeforeLast('/', "").ifEmpty { "/" }

private fun filesUrl(host: Host, path: String) = "/hosts/${host.id}/files?path=${enc(path)}"

private fun enc(value: String): String = URLEncoder.encode(value, Charsets.UTF_8)

private fun humanSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KiB".format(bytes / 1024.0)
    bytes < 1024L * 1024 * 1024 -> "%.1f MiB".format(bytes / 1024.0 / 1024)
    else -> "%.1f GiB".format(bytes / 1024.0 / 1024 / 1024)
}
