package bayern.kickner.dirl.web

import bayern.kickner.dirl.config.UnlockMode
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.vault.MIN_PASSPHRASE_LENGTH
import bayern.kickner.dirl.vault.MIN_PASSPHRASE_WORDS
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
import kotlinx.html.FormEncType
import kotlinx.html.FormMethod
import kotlinx.html.details
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
 * - `POST /unlock` unlocks. Argon2 runs on a worker thread.
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
        val error = bytes?.let { dirl.vault.restore(it, call.session.actor) } ?: "No file uploaded"
        if (error == null) call.respondRedirect("/unlock?done=restored")
        else call.setupPage(dirl, error)
    }

    post("/unlock") {
        val passphrase = call.receiveParameters()["passphrase"].orEmpty()
        val result = withContext(Dispatchers.Default) { dirl.vault.unlock(passphrase.toCharArray(), call.session.actor) }
        when (result) {
            is ResultOf2.Success -> call.respondRedirect("/")
            is ResultOf2.Failure -> call.unlockPage(dirl, unlockErrorText(result.value))
        }
    }
}

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

private suspend fun ApplicationCall.unlockPage(dirl: Dirl, error: String?) =
    page("Unlock", session, frame = PageFrame.CENTER, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        centerCard {
            pageHeader("Unlock vault")
            if (error != null) notice("error", error)
            if (dirl.config.unlockMode == UnlockMode.KEYFILE && error == null) {
                notice("warn", "Key file mode is configured, but the automatic unlock at startup failed. See the log.")
            }
            p("muted") { +"Dirl was restarted and is sealed. Enter the vault passphrase to load hosts and keys." }
            form(action = "/unlock", method = FormMethod.post, classes = "form") {
                passwordField("Passphrase", "passphrase", "current-password")
                submit("Unlock")
            }
        }
    }
