package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.randomToken
import bayern.kickner.dirl.ssh.MAX_LIST_BYTES
import bayern.kickner.dirl.ssh.describe
import bayern.kickner.dirl.ssh.describeChannelError
import bayern.kickner.dirl.ssh.openSftp
import bayern.kickner.dirl.vault.Host
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
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
import kotlinx.coroutines.NonCancellable
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
import net.schmizz.sshj.sftp.RemoteFile
import net.schmizz.sshj.sftp.RemoteResourceFilter
import net.schmizz.sshj.sftp.RemoteResourceInfo
import net.schmizz.sshj.sftp.RenameFlags
import net.schmizz.sshj.sftp.Response
import net.schmizz.sshj.sftp.SFTPClient
import net.schmizz.sshj.sftp.SFTPException
import java.io.IOException
import java.io.InputStream
import java.net.URLEncoder
import java.util.EnumSet

private const val TAG = "FileRoutes"

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
 * A host marked jump host only answers every one of them with [jumpOnlyPage], see [fileHostOr404].
 *
 * Contents are moved as bytes, nothing guesses encodings. There is no editor in the browser, files are changed in the
 * terminal. Uploads write to a temporary file next to the target and rename it only once the multipart body shows
 * that the file arrived completely: the next part starts or the body ends with its closing boundary. Ktor ends a cut
 * off part like a complete one, so the boundary is the only proof. A transfer that breaks off removes the temporary
 * file of the file in progress and leaves its target unchanged. Files before it whose next part already started stay,
 * a break inside the headers of the next part discards the file before it as well. Every replaced target is audited
 * right after its rename. Ktor only checks for the closing boundary when the request carries a `Content-Length`, which
 * browsers always send. Without it (chunked, or a body that ends with the connection) a cut off body looks complete,
 * the truncated file replaces its target and is audited as a normal upload. Accepted, such clients are scripts.
 */
fun Route.fileRoutes(dirl: Dirl) {
    get("/hosts/{id}/files") {
        val host = fileHostOr404(dirl) ?: return@get
        val requested = call.request.queryParameters["path"]
        val listing = withSftp(dirl, host, maxTotalBytes = MAX_LIST_BYTES) { sftp ->
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
        val host = fileHostOr404(dirl) ?: return@get
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
                // Up to 17 reads of 32 KiB in flight (sshj sends one more than the number given) instead of one 8 KiB
                // read per round trip, like the upload's writes.
                remote.ReadAheadRemoteFileInputStream(16).use { it.copyTo(this, 32 * 1024) }
            } finally {
                runCatching { remote.close() }
                runCatching { sftp.close() }
            }
        }
    }

    post("/hosts/{id}/files/upload") {
        val host = fileHostOr404(dirl) ?: return@post
        val dir = call.request.queryParameters["path"].orEmpty()
        val client = connectedClient(dirl, host) ?: return@post
        val uploaded = mutableListOf<String>()
        val failed = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        // The checkbox is placed before the file input, so it arrives before the files in the multipart body.
        var overwrite = false

        val channel = withContext(Dispatchers.IO) { runCatching { client.openSftp() } }
        channel.getOrElse { return@post call.fileError(host, describeChannelError(it)) }.use { sftp ->
            // A file waits under its temporary name until the multipart body shows that it arrived completely.
            var pending: PendingUpload? = null

            suspend fun commitPending() {
                val upload = pending ?: return
                pending = null
                // Not cancellable: once the target is replaced, the change has to reach the audit log.
                val error = withContext(NonCancellable + Dispatchers.IO) {
                    runCatching { commitWrite(sftp, upload.write, overwrite) }
                        .onSuccess { dirl.audit.record(call.session.actor, AuditAction.SFTP_UPLOAD, host.name, upload.target) }
                        .exceptionOrNull()
                }
                // The reason matters, for example "Permission denied" or a file of another owner.
                if (error == null) uploaded += upload.target else failed += "${upload.name} (${describeChannelError(error)})"
            }

            try {
                call.receiveMultipart(formFieldLimit = MAX_UPLOAD_BYTES).forEachPart { part ->
                    // A slow upload may outlast the user's access, nothing more is written after it ended. The pending
                    // file is discarded below.
                    call.ensureStillAuthorized(dirl)
                    // A part only starts after the boundary that ends the one before, so the pending file is complete.
                    commitPending()
                    if (part is PartData.FormItem && part.name == "overwrite") overwrite = part.value == "on"
                    if (part is PartData.FileItem) {
                        val name = safeFileName(part.originalFileName)
                        val target = "${dir.trimEnd('/')}/$name"
                        val exists = name != null && withContext(Dispatchers.IO) { runCatching { sftp.statExistence(target) != null }.getOrDefault(false) }
                        when {
                            name == null -> failed += (part.originalFileName ?: "unnamed")
                            exists && overwrite.not() -> skipped += name
                            else -> {
                                val error = withContext(Dispatchers.IO) {
                                    // Kept as pending inside the block, so a cancellation right after the write still finds it.
                                    runCatching { part.provider().toInputStream().use { pending = PendingUpload(name, target, writeTemporary(sftp, target, it)) } }.exceptionOrNull()
                                }
                                if (error != null) failed += "$name (${describeChannelError(error)})"
                            }
                        }
                    }
                    part.release()
                }
                // With a Content-Length forEachPart only returns normally after the closing boundary, so the last file
                // is complete as well. Without one a cut off body also ends here, see the KDoc of fileRoutes.
                call.ensureStillAuthorized(dirl)
                commitPending()
            } finally {
                // The body broke off: Ktor ends a cut off part like a complete one, only the missing boundary shows it.
                pending?.let { upload ->
                    val discarded = withContext(NonCancellable + Dispatchers.IO) { discardWrite(sftp, upload.write) }
                    if (discarded) staticLog(KLogger.Level.WARN, TAG) { "Upload of ${upload.target} to ${host.name} broke off, nothing was changed" }
                    else staticLog(KLogger.Level.WARN, TAG) { "Upload of ${upload.target} to ${host.name} broke off, cannot remove ${upload.write.tmp}" }
                }
            }
        }
        if (failed.isEmpty() && skipped.isEmpty()) return@post call.respondRedirect(filesUrl(host, dir) + "&done=uploaded")
        val message = listOfNotNull(
            failed.takeIf { it.isNotEmpty() }?.let { "Failed: ${it.joinToString()}." },
            skipped.takeIf { it.isNotEmpty() }?.let { "Already exist, not overwritten: ${it.joinToString()}. Tick \"Overwrite existing files\" to replace them." },
            uploaded.takeIf { it.isNotEmpty() }?.let { "Uploaded: ${it.size} file(s)." },
        ).joinToString(" ")
        call.fileError(host, message)
    }

    post("/hosts/{id}/files/mkdir") {
        val host = fileHostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val dir = form["dir"].orEmpty()
        val name = safeFileName(form["name"]) ?: return@post call.respondRedirect(filesUrl(host, dir))
        val path = "${dir.trimEnd('/')}/$name"
        withSftp(dirl, host) { it.mkdir(path) } ?: return@post
        dirl.audit.record(call.session.actor, AuditAction.SFTP_MKDIR, host.name, path)
        call.respondRedirect(filesUrl(host, dir) + "&done=created")
    }

    post("/hosts/{id}/files/delete") {
        val host = fileHostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val path = form["path"].orEmpty()
        withSftp(dirl, host) { sftp -> deleteEntry(sftp, path) } ?: return@post
        dirl.audit.record(call.session.actor, AuditAction.SFTP_DELETE, host.name, path)
        call.respondRedirect(filesUrl(host, form["dir"].orEmpty()) + "&done=deleted")
    }

    get("/hosts/{id}/files/rename") {
        val host = fileHostOr404(dirl) ?: return@get
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
        val host = fileHostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val path = form["path"].orEmpty()
        val target = form["target"].orEmpty().trim()
        if (target.isEmpty() || target == path) return@post call.respondRedirect(filesUrl(host, parentOf(path)))
        // OpenSSH refuses a rename onto an existing entry with a bare "Failure", or replaces a dangling symlink, so the
        // check gives a clear message. On servers whose rename overwrites, it is the only guard (an entry created in
        // between still gets replaced there).
        val renamed = withSftp(dirl, host) { sftp ->
            val free = entryExists(sftp, target).not()
            if (free) sftp.rename(path, target)
            free
        } ?: return@post
        if (renamed.not()) return@post call.fileError(host, "$target already exists. Choose another name, existing entries are not overwritten.")
        dirl.audit.record(call.session.actor, AuditAction.SFTP_RENAME, host.name, "$path to $target")
        call.respondRedirect(filesUrl(host, parentOf(target)) + "&done=renamed")
    }
}

/**
 * Like [hostOr404], but a host marked jump host only gets [jumpOnlyPage] instead: it offers no files, also not to a
 * request typed by hand. Otherwise only the `authorized_keys` line on the server would stop it.
 *
 * @return the host, or `null` after a page was sent.
 */
private suspend fun RoutingContext.fileHostOr404(dirl: Dirl): Host? {
    val (_, host) = hostOr404(dirl) ?: return null
    if (host.jumpOnly.not()) return host
    call.jumpOnlyPage(host)
    return null
}

/**
 * Runs [block] with a fresh SFTP channel on the host's connection. Errors are rendered as an error page.
 *
 * @return the block's result, or `null` after an error page was sent.
 */
private suspend fun <T : Any> RoutingContext.withSftp(dirl: Dirl, host: Host, maxTotalBytes: Long = Long.MAX_VALUE, block: (SFTPClient) -> T): T? {
    val client = connectedClient(dirl, host) ?: return null
    return withContext(Dispatchers.IO) { runCatching { client.openSftp(maxTotalBytes).use(block) } }
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
 * the limit is passed instead of letting a hostile server fill the heap. The bytes are capped by the channel, see
 * [MAX_LIST_BYTES].
 *
 * @throws IllegalStateException with a message for the user if the directory has more than [max] entries.
 * @throws IOException if reading failed, for example at the byte limit. The channel is unusable then, close it.
 */
fun listDirectory(sftp: SFTPClient, dir: String, max: Int = MAX_LIST_ENTRIES): List<RemoteResourceInfo> {
    var count = 0
    val listing = sftp.sftpEngine.openDir(dir)
    val entries = runCatching {
        listing.scan(RemoteResourceFilter {
            count++
            check(count <= max) { "This directory has more than $max entries. Dirl does not list it, use the terminal instead." }
            true
        })
    }.onFailure { error ->
        // A failed read ends sshj's reader thread, a CLOSE would wait 30 seconds for an answer nobody reads. Closing
        // the whole channel, as the caller does, releases the handle on the server as well.
        if (error !is IOException) runCatching { listing.close() }
    }.getOrThrow()
    listing.close()
    return entries
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
 * A file of an upload, written under its temporary name and waiting for [commitWrite] or [discardWrite].
 *
 * @property name File name as uploaded, for messages.
 * @property target The path the upload route was asked to write, for the audit log.
 * @property write The temporary file.
 */
private class PendingUpload(val name: String, val target: String, val write: TemporaryWrite)

/**
 * New content written to [tmp] next to [target], see [writeTemporary]. [target] is unchanged until [commitWrite].
 *
 * @property target The file the content is meant for, a symlink already resolved.
 * @property tmp The temporary file, `<dir>/.<name>.dirl-tmp-<random>`.
 */
class TemporaryWrite(val target: String, val tmp: String)

/**
 * Writes [input] to [path] in two steps: [writeTemporary] and [commitWrite]. A caller that cannot tell yet whether
 * [input] is complete uses the two steps directly and calls [discardWrite] instead of committing.
 *
 * @param overwrite Replace an existing [path]. Without it the write fails if [path] exists by the time of the commit.
 */
fun writeAtomically(sftp: SFTPClient, path: String, input: InputStream, overwrite: Boolean = true) =
    commitWrite(sftp, writeTemporary(sftp, path, input), overwrite)

/**
 * Writes [input] to `<dir>/.<name>.dirl-tmp-<random>` next to [path] and leaves [path] itself unchanged.
 *
 * A symlink as [path] is resolved first, so the file it points to is written and the link stays. Writing to the
 * link path itself would replace the link with a plain file and leave the real file unchanged.
 *
 * An existing target keeps its permissions, owner and group. The temporary file is created with the target's
 * permissions, so a private key is never readable by others in between. If the SSH user may not give the file the
 * target's owner or group, the write is refused and the target stays unchanged. Changing a file of another user
 * needs a login as that user.
 *
 * The directory may be writable by others. The temporary name is random and created with `EXCL`, so an entry planted
 * there beforehand, a symlink or a file somebody keeps open, is never written. Owner and permissions are set through
 * the open handle, so swapping the temporary file for a symlink cannot redirect them either.
 *
 * A failed write removes the temporary file again, a broken upload would otherwise leave a large hidden file on a
 * possibly full file system. Errors are rethrown.
 */
fun writeTemporary(sftp: SFTPClient, path: String, input: InputStream): TemporaryWrite {
    val target = resolveLink(sftp, path)
    val tmp = target.substringBeforeLast('/', ".") + "/." + target.substringAfterLast('/') + ".dirl-tmp-" + randomToken(6)
    val existing = sftp.statExistence(target)
    val permissions = existing?.let { FileAttributes.Builder().withPermissions(it.mode.permissionsMask).build() }
    // Fails without creating anything if the name is taken, so there is nothing of ours to remove then.
    val file = sftp.open(tmp, EnumSet.of(OpenMode.WRITE, OpenMode.CREAT, OpenMode.EXCL), permissions ?: FileAttributes.EMPTY)
    runCatching {
        file.use {
            file.RemoteFileOutputStream(0, 16).use { input.copyTo(it) }
            if (existing != null) keepAttributes(file, target, existing)
        }
    }.onFailure { error -> discardAndThrow(sftp, tmp, error) }
    return TemporaryWrite(target, tmp)
}

/**
 * Renames the temporary file of [write] to its target. With [overwrite] an existing target is replaced through
 * OpenSSH's `posix-rename` extension. Only a server without that extension gets the target removed first, then the
 * temporary file holds the only copy of the new content and stays if the rename fails. Without [overwrite] a plain
 * rename is used, which OpenSSH refuses for an existing target, so a file created since the upload checked stays.
 * Any other failure removes the temporary file and leaves the target unchanged. Errors are rethrown.
 */
fun commitWrite(sftp: SFTPClient, write: TemporaryWrite, overwrite: Boolean) {
    if (overwrite.not() || sftp.sftpEngine.supportsServerExtension("posix-rename", "openssh.com")) {
        val flags = if (overwrite) setOf(RenameFlags.OVERWRITE) else emptySet()
        runCatching { sftp.rename(write.tmp, write.target, flags) }.onFailure { error ->
            val appeared = overwrite.not() && runCatching { entryExists(sftp, write.target) }.getOrDefault(false)
            discardAndThrow(sftp, write.tmp, if (appeared) IllegalStateException("it was created by somebody else during the upload and is not overwritten", error) else error)
        }
        return
    }
    runCatching { if (sftp.statExistence(write.target) != null) sftp.rm(write.target) }.onFailure { error -> discardAndThrow(sftp, write.tmp, error) }
    sftp.rename(write.tmp, write.target)
}

/**
 * Removes the temporary file of [write], its target stays unchanged.
 *
 * @return `false` if the temporary file could not be removed and is still there.
 */
fun discardWrite(sftp: SFTPClient, write: TemporaryWrite): Boolean = runCatching { sftp.rm(write.tmp) }.isSuccess

/**
 * Gives the open [file] the owner, group and permissions of [original], through the handle and never by path. The
 * owner comes first because changing it clears the setuid and setgid bits, and the permissions are set again because
 * the server's umask applies when creating.
 *
 * @throws IllegalStateException with a message for the user if the owner or group cannot be kept.
 */
private fun keepAttributes(file: RemoteFile, target: String, original: FileAttributes) {
    val created = file.fetchAttributes()
    if (created.uid != original.uid || created.gid != original.gid) runCatching {
        file.setAttributes(FileAttributes.Builder().withUIDGID(original.uid, original.gid).build())
    }.onFailure { error ->
        throw IllegalStateException("$target belongs to another user or group (${original.uid}:${original.gid}) that this login cannot keep. Log in as its owner to change it.", error)
    }
    file.setAttributes(FileAttributes.Builder().withPermissions(original.mode.permissionsMask).build())
}

/** Whether anything exists at [path], a dangling symlink included. `stat` follows links and misses a dangling one. */
private fun entryExists(sftp: SFTPClient, path: String): Boolean = runCatching { sftp.lstat(path) }.fold(
    onSuccess = { true },
    onFailure = { error -> if ((error as? SFTPException)?.statusCode == Response.StatusCode.NO_SUCH_FILE) false else throw error },
)

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
