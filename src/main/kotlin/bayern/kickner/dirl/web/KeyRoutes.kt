package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.ssh.KEY_COMMENT
import bayern.kickner.dirl.ssh.fingerprintOfLine
import bayern.kickner.dirl.ssh.generateEd25519Key
import bayern.kickner.dirl.ssh.importPrivateKey
import bayern.kickner.dirl.vault.SshKey
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.header
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.FormMethod
import kotlinx.html.details
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.summary
import kotnexlib.ResultOf2

/**
 * SSH key management.
 *
 * - `GET /keys` lists keys with fingerprint, usage and public key.
 * - `POST /keys/generate` creates an Ed25519 key, `POST /keys/import` imports an unencrypted private key.
 * - `POST /keys/{id}/rename`, `POST /keys/{id}/delete` (only for keys no host uses).
 * - `GET /keys/{id}/export`, `POST /keys/{id}/export` downloads the private key after the vault passphrase was
 *   entered again. Failed attempts count towards the unlock lockout.
 */
fun Route.keyRoutes(dirl: Dirl) {
    get("/keys") { call.keysPage(dirl, null) }

    post("/keys/generate") {
        val name = call.receiveParameters()["name"].orEmpty().trim().take(64).ifEmpty { "dirl" }
        val key = generateEd25519Key(name)
        dirl.vault.update { it.copy(keys = it.keys + key) }
        dirl.audit.record(call.session.actor, AuditAction.KEY_GENERATED, detail = name)
        call.respondRedirect("/keys?done=key-generated")
    }

    post("/keys/import") {
        val form = call.receiveParameters()
        val name = form["name"].orEmpty().trim().take(64).ifEmpty { "imported" }
        when (val imported = importPrivateKey(name, form["privateKey"].orEmpty())) {
            is ResultOf2.Failure -> call.keysPage(dirl, imported.value, importOpen = true)
            is ResultOf2.Success -> {
                dirl.vault.update { it.copy(keys = it.keys + imported.value) }
                dirl.audit.record(call.session.actor, AuditAction.KEY_IMPORTED, detail = name)
                call.respondRedirect("/keys?done=key-imported")
            }
        }
    }

    post("/keys/{id}/rename") {
        val id = call.parameters["id"].orEmpty()
        val name = call.receiveParameters()["name"].orEmpty().trim().take(64)
        val key = dirl.vault.content?.key(id)
        if (key != null && name.isNotEmpty()) {
            dirl.vault.update { c -> c.copy(keys = c.keys.map { if (it.id == id) it.copy(name = name) else it }) }
            dirl.audit.record(call.session.actor, AuditAction.KEY_RENAMED, detail = "${key.name} to $name")
        }
        call.respondRedirect("/keys?done=key-renamed")
    }

    post("/keys/{id}/delete") {
        val id = call.parameters["id"].orEmpty()
        val content = dirl.vault.content ?: return@post
        val key = content.key(id) ?: return@post call.respondRedirect("/keys")
        val users = content.hosts.filter { it.keyId == id }
        if (users.isNotEmpty()) return@post call.keysPage(dirl, "${key.name} is used by ${users.joinToString { it.name }}. Change those hosts first.")
        dirl.vault.update { c -> c.copy(keys = c.keys.filterNot { it.id == id }) }
        dirl.audit.record(call.session.actor, AuditAction.KEY_DELETED, detail = key.name)
        call.respondRedirect("/keys?done=key-deleted")
    }

    get("/keys/{id}/export") {
        val key = dirl.vault.content?.key(call.parameters["id"].orEmpty()) ?: return@get call.respondRedirect("/keys")
        call.exportPage(key, null)
    }

    post("/keys/{id}/export") {
        val key = dirl.vault.content?.key(call.parameters["id"].orEmpty()) ?: return@post call.respondRedirect("/keys")
        val passphrase = call.receiveParameters()["passphrase"].orEmpty()
        val check = withContext(Dispatchers.Default) { dirl.vault.verifyPassphrase(passphrase.toCharArray(), call.session.actor) }
        if (check is ResultOf2.Failure) return@post call.exportPage(key, unlockErrorText(check.value))

        dirl.audit.record(call.session.actor, AuditAction.KEY_EXPORTED, detail = key.name)
        val fileName = key.name.replace(Regex("[^A-Za-z0-9._-]"), "_").ifEmpty { "key" }
        call.response.header(
            HttpHeaders.ContentDisposition,
            ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, "id_$fileName").toString(),
        )
        call.respondText(key.privateKeyPem, ContentType.Application.OctetStream)
    }
}

/**
 * The keys page: adding a key on top, the existing keys below as folded rows. Right after a generate or import
 * redirect the newest key is open, so its public key can be copied at once.
 *
 * @param error Shown above the page, `null` for none.
 * @param importOpen Opens the import form, for an import that failed.
 */
private suspend fun ApplicationCall.keysPage(dirl: Dirl, error: String?, importOpen: Boolean = false) {
    val content = dirl.vault.content ?: return
    val from = content.settings.sshSourceAddress ?: "<DIRL-IP>"
    val justAdded = request.queryParameters["done"]
        ?.takeIf { it == "key-generated" || it == "key-imported" }
        ?.let { content.keys.maxByOrNull(SshKey::createdAt)?.id }
    page("Keys", session, Nav.KEYS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Keys", "Use keys that exist only for Dirl, never your personal key.")
        if (error != null) notice("error", error)
        div("stack") {
            card("Add a key") {
                form(action = "/keys/generate", method = FormMethod.post, classes = "btn-row key-add") {
                    textField("Name", "name", "dirl")
                    submit("Generate key")
                }
                p("muted small") { +"Ed25519, generated on this server. The private key never leaves the vault unless you export it." }
                details("import") {
                    if (importOpen) attributes["open"] = "open"
                    summary { +"Import existing key" }
                    form(action = "/keys/import", method = FormMethod.post, classes = "form") {
                        textField("Name", "name", "", placeholder = "legacy-key")
                        textAreaField(
                            "Private key", "privateKey", rows = 6,
                            hint = "Unencrypted OpenSSH or PEM. Remove a passphrase first with ssh-keygen -p -N \"\" -f <file>.",
                        )
                        div("btn-row") { submit("Import", "") }
                    }
                }
            }

            if (content.keys.isEmpty()) notice("info", "No keys yet. Generate one above, then add your first host.")
            else card(classes = "key-list") {
                content.keys.sortedBy { it.name.lowercase() }.forEach { key ->
                    val users = content.hosts.filter { it.keyId == key.id }
                    details("key-row") {
                        if (key.id == justAdded) attributes["open"] = "open"
                        summary {
                            span("key-name") { +key.name }
                            span("key-fp mono") { +fingerprintOfLine(key.publicKey) }
                            if (users.isEmpty()) pill("", "unused")
                            else pill("ok", if (users.size == 1) "1 host" else "${users.size} hosts")
                        }
                        div("key-body") {
                            keyValues(
                                "Created" to formatTimestamp(key.createdAt),
                                "Used by" to users.joinToString { it.name }.ifEmpty { "nobody" },
                            )
                            p("muted small") { +"Public key, for a normal target (each host page shows the exact line for that host):" }
                            copyBlock("restrict,pty,from=\"$from\" ${key.publicKey} $KEY_COMMENT")
                            form(action = "/keys/${key.id}/rename", method = FormMethod.post, classes = "btn-row key-add") {
                                textField("Name", "name", key.name)
                                submit("Rename", "")
                            }
                            div("btn-row") {
                                linkButton("/keys/${key.id}/export", "Export private key")
                                if (users.isEmpty()) postButton("/keys/${key.id}/delete", "Delete", "danger", confirm = "Delete key ${key.name}? This cannot be undone.")
                                else span("muted small") { +"In use, cannot be deleted." }
                            }
                        }
                    }
                }
            }
        }
    }
}

private suspend fun ApplicationCall.exportPage(key: SshKey, error: String?) =
    page("Export ${key.name}", session, Nav.KEYS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Export ${key.name}", "Download the unencrypted private key.")
        if (error != null) notice("error", error)
        card {
            notice("warn", "Anyone with this file can log in wherever the key is authorized. Store it encrypted, e.g. in your password manager.")
            form(action = "/keys/${key.id}/export", method = FormMethod.post, classes = "form") {
                passwordField("Vault passphrase", "passphrase", "current-password", hint = "Required again for every export.")
                div("btn-row") {
                    submit("Download")
                    linkButton("/keys", "Cancel", "ghost")
                }
            }
        }
    }
