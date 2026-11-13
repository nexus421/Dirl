package bayern.kickner.dirl.web

import bayern.kickner.dirl.config.UnlockMode
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.vault.KeyFileWrap
import bayern.kickner.dirl.vault.MIN_PASSPHRASE_LENGTH
import bayern.kickner.dirl.vault.MIN_PASSPHRASE_WORDS
import bayern.kickner.dirl.vault.SealReason
import bayern.kickner.dirl.vault.SetupError
import bayern.kickner.dirl.vault.UnlockError
import bayern.kickner.dirl.vault.VaultState
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveMultipart
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.jvm.javaio.toInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.ButtonType
import kotlinx.html.FlowContent
import kotlinx.html.FormEncType
import kotlinx.html.FormMethod
import kotlinx.html.button
import kotlinx.html.details
import kotlinx.html.div
import kotlinx.html.fileInput
import kotlinx.html.form
import kotlinx.html.label
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.summary
import kotnexlib.ResultOf2

/** Largest vault backup accepted for restore. A vault with hundreds of hosts and keys is far below. */
private const val MAX_RESTORE_BYTES = 10L * 1024 * 1024

/**
 * Vault lifecycle before the app can be used.
 *
 * - `GET /unlock` shows the setup form (no vault yet) or the unlock form (sealed).
 * - `POST /setup` creates the vault, the current user becomes its first allowed user.
 * - `POST /setup/restore` restores an encrypted backup instead (only while no vault exists).
 * - `POST /unlock` unlocks. Argon2 runs on a worker thread. With `keyfile=fix` it also brings the key file wrap in
 *   line with the unlock mode, see [KeyFileWrap], the unlock page explains that first.
 *
 * Passphrases arrive as form fields, which Ktor hands over as `String`. Those cannot be wiped, the arrays derived
 * from them are. The real protection is that the passphrase never leaves the request handling and is never logged.
 */
fun Route.vaultRoutes(dirl: Dirl) {
    get("/unlock") {
        when (dirl.vault.state) {
            VaultState.Uninitialized -> call.setupPage(dirl, null)
            VaultState.Sealed -> call.unlockPage(dirl, null)
            is VaultState.Unlocked -> call.respondRedirect("/")
        }
    }

    post("/setup") {
        val form = call.receiveParameters()
        val passphrase = form["passphrase"].orEmpty()
        if (passphrase != form["confirm"].orEmpty()) return@post call.setupPage(dirl, "The passphrases do not match.")

        val result = withContext(Dispatchers.Default) { dirl.vault.setup(passphrase.toCharArray(), call.session.actor) }
        when (result) {
            is ResultOf2.Success -> call.respondRedirect("/")
            is ResultOf2.Failure -> call.setupPage(
                dirl,
                when (val e = result.value) {
                    SetupError.AlreadySetUp -> "A vault already exists."
                    is SetupError.PassphraseTooWeak -> e.reason
                    is SetupError.KeyFileUnavailable -> e.reason
                },
            )
        }
    }

    post("/setup/restore") {
        var bytes: ByteArray? = null
        call.receiveMultipart(formFieldLimit = MAX_RESTORE_BYTES).forEachPart { part ->
            if (part is PartData.FileItem && bytes == null) {
                bytes = withContext(Dispatchers.IO) { part.provider().toInputStream().use { it.readNBytes(MAX_RESTORE_BYTES.toInt()) } }
            }
            part.release()
        }
        val upload = bytes ?: return@post call.setupPage(dirl, "No file uploaded")
        val actor = call.session.actor
        when (val error = dirl.vault.restore(upload, actor)) {
            null -> {
                dirl.access.allowUntilUnlock(actor.sub, actor.name)
                call.respondRedirect("/unlock?done=restored")
            }

            else -> call.setupPage(dirl, error)
        }
    }

    post("/unlock") {
        val form = call.receiveParameters()
        val passphrase = form["passphrase"].orEmpty()
        // Only the button under the explanation on the unlock page sends this, never the Enter key.
        val fix = form["keyfile"] == "fix"
        val (result, done) = withContext(Dispatchers.Default) {
            val before = if (fix) dirl.vault.keyFileWrap() else KeyFileWrap.FITS
            val result = dirl.vault.unlock(passphrase.toCharArray(), call.session.actor, fixKeyFileWrap = fix)
            val done = when {
                before !in keyFileMismatch || dirl.vault.keyFileWrap() != KeyFileWrap.FITS -> ""
                before == KeyFileWrap.MISSING -> "?done=keyfile-added"
                else -> "?done=rekeyed"
            }
            result to done
        }
        when (result) {
            is ResultOf2.Success -> call.respondRedirect("/$done")
            is ResultOf2.Failure -> call.unlockPage(dirl, unlockErrorText(result.value))
        }
    }
}

/** Key file wraps the unlock page explains and offers to fix, see [KeyFileWrap]. */
private val keyFileMismatch = setOf(KeyFileWrap.LEFT_OVER, KeyFileWrap.FOREIGN, KeyFileWrap.MISSING)

/** User-facing text for a failed unlock or passphrase check. */
fun unlockErrorText(error: UnlockError): String = when (error) {
    UnlockError.NotSealed -> "The vault is not in the expected state."
    is UnlockError.WrongPassphrase -> "Wrong passphrase. ${error.attemptsLeft} attempt(s) left before a 15 minute lockout."
    is UnlockError.LockedOut -> "Too many wrong passphrases. Try again after ${formatTimestamp(error.untilMillis)}."
    is UnlockError.Unusable -> error.reason
}

private suspend fun ApplicationCall.setupPage(dirl: Dirl, error: String?) =
    page("Create vault", session, frame = PageFrame.CENTER, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        centerCard {
            pageHeader("Create vault")
            if (error != null) notice("error", error)
            p("muted") {
                +"Hosts and keys are stored encrypted with a key derived from this passphrase. Keep it in your password "
                +"manager. Without it the vault cannot be opened, there is no recovery."
            }
            if (dirl.config.unlockMode == UnlockMode.KEYFILE) notice("info", "Key file mode: the vault will also unlock itself at startup with ${dirl.config.keyFile}.")
            form(action = "/setup", method = FormMethod.post, classes = "form") {
                passwordField(
                    "Passphrase", "passphrase", "new-password",
                    hint = "At least $MIN_PASSPHRASE_LENGTH characters or $MIN_PASSPHRASE_WORDS Diceware words.",
                )
                passwordField("Repeat passphrase", "confirm", "new-password")
                submit("Create vault")
            }
            details {
                summary { +"Restore an encrypted backup instead" }
                form(action = "/setup/restore", method = FormMethod.post, encType = FormEncType.multipartFormData, classes = "form") {
                    p("muted small") { +"A vault backup downloaded under Settings, or a copy of vault.json. Afterwards it unlocks with its own passphrase." }
                    label("field") {
                        span { +"Backup file" }
                        fileInput(name = "backup") { required = true; accept = ".json,application/json" }
                    }
                    submit("Restore", "")
                }
            }
        }
    }

private suspend fun ApplicationCall.unlockPage(dirl: Dirl, error: String?) {
    val wrap = withContext(Dispatchers.Default) { dirl.vault.keyFileWrap() }
    page("Unlock", session, frame = PageFrame.CENTER, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        centerCard {
            pageHeader("Unlock vault")
            if (error != null) notice("error", error)
            val reason = dirl.vault.sealReason
            if (wrap in keyFileMismatch) keyFileNotice(wrap, dirl.config.keyFile)
            else if (reason == SealReason.KEY_FILE_FAILED && error == null) {
                notice("warn", "Key file mode is configured, but the automatic unlock at startup failed. See the log.")
            }
            p("muted") {
                +when (reason) {
                    SealReason.STARTED, SealReason.KEY_FILE_FAILED -> "Dirl was restarted and is sealed. Enter the vault passphrase to load hosts and keys."
                    SealReason.BY_USER -> "The vault was sealed under Settings. Enter the vault passphrase to load hosts and keys." +
                        if (dirl.config.unlockMode == UnlockMode.KEYFILE) " Or restart Dirl to unlock it with the key file." else ""
                    SealReason.RESTORED -> "The vault was restored from a backup. Enter the passphrase it was created with to load hosts and keys."
                }
            }
            form(action = "/unlock", method = FormMethod.post, classes = "form") {
                passwordField("Passphrase", "passphrase", "current-password")
                if (wrap in keyFileMismatch) div("btn-row") {
                    // The first button is the one the Enter key presses, so only a click changes the vault.
                    submit("Only unlock", "")
                    button(type = ButtonType.submit, classes = "btn primary") {
                        name = "keyfile"
                        value = "fix"
                        +if (wrap == KeyFileWrap.MISSING) "Unlock and add key file" else "Unlock and re-encrypt"
                    }
                }
                else submit("Unlock")
            }
        }
    }
}

/** Explains a key file wrap that does not fit the unlock mode and what the two unlock buttons do about it. */
private fun FlowContent.keyFileNotice(wrap: KeyFileWrap, keyFile: String) {
    notice(
        "warn",
        when (wrap) {
            KeyFileWrap.LEFT_OVER -> "Passphrase mode is configured, but a key file from before still opens this vault."
            KeyFileWrap.FOREIGN -> "The key file $keyFile does not open this vault, another key file does. It was replaced, or the vault comes from another server."
            else -> "Key file mode is configured, but $keyFile does not open this vault yet."
        },
    )
    p("small") {
        +when (wrap) {
            KeyFileWrap.MISSING -> "Unlock and add key file: Dirl adds $keyFile to the vault and unlocks itself with it at the next start. "
            KeyFileWrap.FOREIGN -> "Unlock and re-encrypt: the vault gets a new key that opens with the passphrase and $keyFile. " +
                "The old key file opens nothing here any more and the local backups vault.json.1 to .3 are deleted. "
            else -> "Unlock and re-encrypt: the vault gets a new key that opens only with the passphrase. " +
                "The old key file opens nothing here any more and the local backups vault.json.1 to .3 are deleted. "
        }
        +"Hosts, keys, snippets and the passphrase stay as they are. Nothing is lost as long as you know the passphrase."
    }
    p("muted small") { +"Only unlock changes nothing, this page asks again next time." }
}
