package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.readAtMost
import bayern.kickner.dirl.ssh.describe
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
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.style
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.textArea
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import kotnexlib.ResultOf2
import net.schmizz.sshj.sftp.FileMode
import net.schmizz.sshj.sftp.OpenMode
import net.schmizz.sshj.sftp.RemoteResourceFilter
import net.schmizz.sshj.sftp.RemoteResourceInfo
import net.schmizz.sshj.sftp.RenameFlags
import net.schmizz.sshj.sftp.SFTPClient
import java.io.InputStream
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.EnumSet

/** Files up to this size can be opened in the text editor. */
const val MAX_EDIT_BYTES = 1L * 1024 * 1024

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
 * - `GET /hosts/{id}/files/edit?path=`, `POST /hosts/{id}/files/save` edit UTF-8 text files up to 1 MiB.
 *
 * Contents are moved as bytes, nothing guesses encodings. The editor refuses files that are not valid UTF-8.
 * Uploads and saves write to a temporary file next to the target and rename it, so a broken transfer never leaves
 * a half-written file behind.
 */
fun Route.fileRoutes(dirl: Dirl) {
    get("/hosts/{id}/files") {
        val (_, host) = hostOr404(dirl) ?: return@get
        if (host.jumpOnly) return@get call.jumpOnlyPage(host)
        val requested = call.request.queryParameters["path"]
        val listing = withSftp(dirl, host) { sftp ->
            val dir = sftp.canonicalize(requested?.trim()?.ifBlank { null } ?: ".")
            dir to listDirectory(sftp, dir).sortedWith(compareBy({ it.isDirectory.not() }, { it.name.lowercase() }))
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
                                        }
                                        td("num") { if (isDir.not()) +humanSize(entry.attributes.size) }
                                        td("nowrap hide-sm muted") { +formatTimestamp(entry.attributes.mtime * 1000) }
                                        td("actions") {
                                            val editable = isDir.not() && entry.attributes.mode.type == FileMode.Type.REGULAR && entry.attributes.size <= MAX_EDIT_BYTES
                                            if (editable) linkButton("/hosts/${host.id}/files/edit?path=${enc(entry.path)}", "Edit", "sm ghost")
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
        val sftp = withContext(Dispatchers.IO) { runCatching { client.newSFTPClient() } }.getOrElse {
            return@get call.fileError(host, it.message ?: "SFTP is not available on this host")
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
                remote.RemoteFileInputStream(0).use { it.copyTo(this) }
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

        withContext(Dispatchers.IO) { client.newSFTPClient() }.use { sftp ->
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
        withSftp(dirl, host) { sftp ->
            val isDir = sftp.stat(path).type == FileMode.Type.DIRECTORY
            if (isDir) runCatching { sftp.rmdir(path) }.getOrElse { error("Only empty directories can be deleted. ${it.message}") }
            else sftp.rm(path)
        } ?: return@post
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

    get("/hosts/{id}/files/edit") {
        val (_, host) = hostOr404(dirl) ?: return@get
        val path = call.request.queryParameters["path"].orEmpty()
        val bytes = withSftp(dirl, host) { sftp ->
            // The size check only saves a pointless read, the server may report a wrong size. The read is capped as well.
            if (sftp.size(path) > MAX_EDIT_BYTES) null
            else sftp.open(path, EnumSet.of(OpenMode.READ)).use { f -> f.RemoteFileInputStream(0).use { it.readAtMost(MAX_EDIT_BYTES.toInt()) } }
        } ?: return@get
        val text = decodeUtf8Strict(bytes) ?: return@get call.fileError(host, "This file is not valid UTF-8 text. Download it instead.")
        call.page("Edit ${path.substringAfterLast('/')}", call.session, Nav.HOSTS, frame = PageFrame.WIDE) {
            form(action = "/hosts/${host.id}/files/save", method = FormMethod.post, classes = "form") {
                div("page-header") {
                    style = "margin:0"
                    p("mono") { style = "margin:0"; +"${host.name}:$path" }
                    div("actions") {
                        submit("Save")
                        linkButton(filesUrl(host, parentOf(path)), "Close", "ghost")
                    }
                }
                hiddenInput(name = "path") { value = path }
                hiddenInput(name = "crlf") { value = text.contains("\r\n").toString() }
                textArea(rows = "30", classes = "editor") {
                    name = "content"
                    attributes["spellcheck"] = "false"
                    attributes["aria-label"] = "File content"
                    // HTML drops one newline right after <textarea>, this keeps a leading empty line of the file.
                    +"\n$text"
                }
            }
        }
    }

    post("/hosts/{id}/files/save") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val path = form["path"].orEmpty()
        // Browsers submit textarea line breaks as CRLF. Restore what the file had before.
        val normalized = form["content"].orEmpty().replace("\r\n", "\n")
        val text = if (form["crlf"] == "true") normalized.replace("\n", "\r\n") else normalized
        withSftp(dirl, host) { sftp -> writeAtomically(sftp, path, text.toByteArray(Charsets.UTF_8).inputStream()) } ?: return@post
        dirl.audit.record(call.session.actor, AuditAction.SFTP_EDIT, host.name, path)
        call.respondRedirect(filesUrl(host, parentOf(path)) + "&done=saved")
    }
}

/**
 * Runs [block] with a fresh SFTP channel on the host's connection. Errors are rendered as an error page.
 *
 * @return the block's result, or `null` after an error page was sent (or when the block itself returned `null`,
 *   e.g. a file too large for the editor, in which case this sends the error page).
 */
private suspend fun <T : Any> RoutingContext.withSftp(dirl: Dirl, host: Host, block: (SFTPClient) -> T?): T? {
    val client = connectedClient(dirl, host) ?: return null
    val result = withContext(Dispatchers.IO) { runCatching { client.newSFTPClient().use(block) } }
    val value = result.getOrNull()
    if (value == null) call.fileError(host, result.exceptionOrNull()?.message ?: "The file is too large or not readable")
    return value
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
 * Writes [input] to `<dir>/.<name>.dirl-tmp` and renames it over [target]. OpenSSH only supports overwriting renames
 * through its `posix-rename` extension, if the server lacks it the target is removed first.
 */
fun writeAtomically(sftp: SFTPClient, target: String, input: InputStream) {
    val tmp = target.substringBeforeLast('/', ".") + "/." + target.substringAfterLast('/') + ".dirl-tmp"
    sftp.open(tmp, EnumSet.of(OpenMode.WRITE, OpenMode.CREAT, OpenMode.TRUNC)).use { file ->
        file.RemoteFileOutputStream(0, 16).use { input.copyTo(it) }
    }
    runCatching { sftp.rename(tmp, target, setOf(RenameFlags.OVERWRITE)) }.getOrElse {
        if (sftp.statExistence(target) != null) sftp.rm(target)
        sftp.rename(tmp, target)
    }
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

/** Decodes [bytes] as UTF-8, `null` if they are not valid UTF-8. */
fun decodeUtf8Strict(bytes: ByteArray): String? = runCatching {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()
}.getOrNull()

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
