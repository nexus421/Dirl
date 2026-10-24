package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.auth.RevokeError
import bayern.kickner.dirl.config.UnlockMode
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.ssh.SOURCE_ADDRESS_PATTERN
import bayern.kickner.dirl.vault.ChangePassphraseError
import bayern.kickner.dirl.vault.MIN_PASSPHRASE_LENGTH
import bayern.kickner.dirl.vault.MIN_PASSPHRASE_WORDS
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.header
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.input
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import kotnexlib.ResultOf2
import java.time.Instant
import java.time.LocalDate

/**
 * Settings and the audit log.
 *
 * - `GET /settings`: allowed users and access requests, active sessions, SSH defaults, passphrase, backup, seal.
 * - `POST /settings/users/allow`, `/settings/users/revoke`, `/settings/requests/dismiss`.
 * - `POST /settings/sessions/revoke`.
 * - `POST /settings/ssh` for the source address used in the `authorized_keys` lines.
 * - `POST /settings/passphrase`, `GET /settings/backup`, `POST /vault/seal`.
 * - `GET /audit?q=` latest audit entries, filterable.
 */
fun Route.settingsRoutes(dirl: Dirl) {
    get("/settings") { call.settingsPage(dirl, null) }

    post("/settings/users/allow") {
        val sub = call.receiveParameters()["sub"].orEmpty()
        // Only pending requests can be allowed, so the name comes from the ID token and not from the form.
        val request = dirl.access.requests.firstOrNull { it.sub == sub } ?: return@post call.respondRedirect("/settings")
        dirl.access.allow(request.sub, request.name, call.session.actor)
        call.respondRedirect("/settings?done=user-allowed")
    }

    post("/settings/users/revoke") {
        val sub = call.receiveParameters()["sub"].orEmpty()
        // Removing yourself would end your own session mid-click, someone else has to do it.
        if (sub == call.session.actor.sub) return@post call.settingsPage(dirl, "You cannot remove yourself.")
        when (val result = dirl.access.revoke(sub, call.session.actor)) {
            is ResultOf2.Success -> {
                // Only for a user who was in the list. A break-glass subject from the config stays logged in.
                if (result.value) dirl.sessions.removeAllFor(sub)
                call.respondRedirect("/settings?done=user-revoked")
            }

            is ResultOf2.Failure -> call.settingsPage(
                dirl,
                when (result.value) {
                    RevokeError.LastUser -> "The last user cannot be removed, nobody could log in any more."
                    RevokeError.NotUnlocked -> "The vault is not unlocked."
                },
            )
        }
    }

    post("/settings/requests/dismiss") {
        dirl.access.dismissRequest(call.receiveParameters()["sub"].orEmpty())
        call.respondRedirect("/settings?done=request-dismissed")
    }

    post("/settings/sessions/revoke") {
        val id = call.receiveParameters()["id"].orEmpty()
        val target = dirl.sessions.list().firstOrNull { it.id == id }
        if (target != null) {
            dirl.sessions.removeById(id)
            dirl.audit.record(call.session.actor, AuditAction.SESSION_REVOKED, detail = target.actor.name)
        }
        val own = target?.token == call.session.token
        // Like a logout: the token is dead anyway, the browser should not keep sending it.
        if (own) call.response.cookies.append(secureCookie(SESSION_COOKIE, "", 0, "Strict"))
        call.respondRedirect(if (own) "/login" else "/settings?done=session-revoked")
    }

    post("/settings/ssh") {
        val value = call.receiveParameters()["sshSourceAddress"].orEmpty().trim()
        if (value.isNotEmpty() && SOURCE_ADDRESS_PATTERN.matches(value).not()) {
            return@post call.settingsPage(dirl, "The source address may only contain addresses, host names, CIDR ranges and wildcards.")
        }
        dirl.vault.update { it.copy(settings = it.settings.copy(sshSourceAddress = value.ifEmpty { null })) }
        dirl.audit.record(call.session.actor, AuditAction.SETTINGS_CHANGED, detail = "sshSourceAddress=${value.ifEmpty { "none" }}")
        call.respondRedirect("/settings?done=settings-saved")
    }

    post("/settings/passphrase") {
        val form = call.receiveParameters()
        val new = form["new"].orEmpty()
        if (new != form["confirm"].orEmpty()) return@post call.settingsPage(dirl, "The new passphrases do not match.")

        val result = withContext(Dispatchers.Default) {
            dirl.vault.changePassphrase(form["old"].orEmpty().toCharArray(), new.toCharArray(), call.session.actor)
        }
        when (result) {
            is ResultOf2.Success -> call.respondRedirect("/settings?done=passphrase-changed")
            is ResultOf2.Failure -> call.settingsPage(
                dirl,
                when (val e = result.value) {
                    ChangePassphraseError.NotUnlocked -> "The vault is not unlocked."
                    is ChangePassphraseError.Refused -> unlockErrorText(e.reason)
                    is ChangePassphraseError.TooWeak -> e.reason
                    is ChangePassphraseError.KeyFileUnavailable -> e.reason
                },
            )
        }
    }

    get("/settings/backup") {
        val bytes = dirl.vault.exportEncrypted() ?: return@get call.respondRedirect("/settings")
        dirl.audit.record(call.session.actor, AuditAction.VAULT_EXPORTED)
        call.response.header(
            HttpHeaders.ContentDisposition,
            ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, "dirl-vault-${LocalDate.now()}.json").toString(),
        )
        call.respondBytes(bytes, ContentType.Application.Json)
    }

    post("/vault/seal") {
        dirl.vault.seal(call.session.actor)
        call.respondRedirect("/unlock")
    }

    get("/audit") {
        val query = call.request.queryParameters["q"].orEmpty().trim()
        val entries = dirl.audit.tail(1000).filter { e ->
            query.isEmpty() || listOf(e.name, e.sub, e.action.name, e.host.orEmpty(), e.detail.orEmpty()).any { it.contains(query, ignoreCase = true) }
        }.take(300)
        call.page("Audit log", call.session, Nav.AUDIT) {
            pageHeader("Audit log", "Every login, change and connection. The full log is audit.jsonl in the data directory.")
            card {
                form(action = "/audit", method = FormMethod.get, classes = "btn-row") {
                    input(type = InputType.search, name = "q") {
                        value = query
                        placeholder = "Filter by user, action, host or detail"
                        attributes["aria-label"] = "Filter"
                    }
                    submit("Filter", "")
                }
            }
            card {
                if (entries.isEmpty()) p("muted") { +"No entries." }
                else div("table-wrap") {
                    table {
                        thead { tr { th { +"Time" }; th { +"User" }; th { +"Action" }; th { +"Host" }; th { +"Detail" } } }
                        tbody {
                            entries.forEach { e ->
                                tr {
                                    td("nowrap") { +(runCatching { formatTimestamp(Instant.parse(e.time).toEpochMilli()) }.getOrDefault(e.time)) }
                                    td { +e.name }
                                    td { span("pill ${auditKind(e.action)}".trim()) { +e.action.name.lowercase().replace('_', ' ') } }
                                    td { +e.host.orEmpty() }
                                    td("muted small") { +e.detail.orEmpty() }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun auditKind(action: AuditAction): String = when (action) {
    AuditAction.LOGIN_REJECTED, AuditAction.VAULT_UNLOCK_FAILED, AuditAction.HOST_KEY_MISMATCH, AuditAction.CONNECTION_STOPPED -> "warn"
    AuditAction.VAULT_LOCKED_OUT -> "error"
    AuditAction.LOGIN, AuditAction.VAULT_UNLOCKED, AuditAction.HOST_KEY_PINNED, AuditAction.USER_ALLOWED -> "ok"
    else -> ""
}

private suspend fun ApplicationCall.settingsPage(dirl: Dirl, error: String?) {
    val content = dirl.vault.content ?: return respondRedirect("/unlock")
    val me = session
    page("Settings", me, Nav.SETTINGS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Settings")
        if (error != null) notice("error", error)
        div("stack") {
            val requests = dirl.access.requests
            if (requests.isNotEmpty()) card("Access requests", "attention") {
                p("muted") { +"These people signed in successfully but have no access yet. Only allow people you know." }
                div("table-wrap") {
                    table {
                        thead { tr { th { +"Name" }; th(classes = "hide-sm") { +"Subject" }; th { +"Requested" }; th { } } }
                        tbody {
                            requests.forEach { request ->
                                tr {
                                    td { +request.name }
                                    td("mono small muted hide-sm") { +request.sub }
                                    td("nowrap") { +formatTimestamp(request.time) }
                                    td("actions") {
                                        postButton("/settings/users/allow", "Allow", "primary sm", hidden = mapOf("sub" to request.sub))
                                        postButton("/settings/requests/dismiss", "Dismiss", "ghost sm", hidden = mapOf("sub" to request.sub))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            card("Users") {
                p("muted") {
                    +"Who may use Dirl, in addition to the group restriction in your identity provider. Everybody here shares the same hosts and keys."
                }
                div("table-wrap") {
                    table {
                        thead { tr { th { +"Name" }; th(classes = "hide-sm") { +"Subject" }; th { +"Since" }; th { } } }
                        tbody {
                            content.settings.allowedUsers.sortedBy { it.name.lowercase() }.forEach { user ->
                                val isMe = user.sub == me.actor.sub
                                tr {
                                    td { +user.name; if (isMe) span("muted small") { +" (you)" } }
                                    td("mono small muted hide-sm") { +user.sub }
                                    td("nowrap") { +formatTimestamp(user.addedAt) }
                                    td("actions") {
                                        if (isMe.not()) postButton(
                                            "/settings/users/revoke", "Remove", "danger sm",
                                            confirm = "Remove access for ${user.name}? Their sessions end immediately.",
                                            hidden = mapOf("sub" to user.sub),
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                p("muted small") { +"New people appear as access requests after their first sign in attempt. You cannot remove yourself, someone else has to." }
            }

            card("Active sessions") {
                div("table-wrap") {
                    table {
                        thead { tr { th { +"User" }; th(classes = "hide-sm") { +"Browser" }; th { +"Signed in" }; th { +"Last activity" }; th { } } }
                        tbody {
                            dirl.sessions.list().forEach { s ->
                                tr {
                                    td { +s.actor.name; if (s.token == me.token) span("muted small") { +" (this browser)" } }
                                    td("muted small hide-sm") { +browserLabel(s.userAgent) }
                                    td("nowrap") { +formatTimestamp(s.createdAt) }
                                    td("nowrap") { +formatTimestamp(s.lastSeen) }
                                    td("actions") { postButton("/settings/sessions/revoke", "End", "sm", hidden = mapOf("id" to s.id)) }
                                }
                            }
                        }
                    }
                }
            }

            div("columns") {
                card("SSH") {
                    form(action = "/settings/ssh", method = FormMethod.post, classes = "form") {
                        textField(
                            "Dirl's source address", "sshSourceAddress", content.settings.sshSourceAddress.orEmpty(),
                            hint = "The address your servers see Dirl connecting from. Fills from=\"...\" in the authorized_keys lines, so a stolen key is useless elsewhere.",
                            required = false, placeholder = "e.g. 192.0.2.10",
                        )
                        div("btn-row") { submit("Save") }
                    }
                }

                card("Passphrase") {
                    form(action = "/settings/passphrase", method = FormMethod.post, classes = "form") {
                        passwordField("Current passphrase", "old", "current-password")
                        passwordField("New passphrase", "new", "new-password", hint = "At least $MIN_PASSPHRASE_LENGTH characters or $MIN_PASSPHRASE_WORDS Diceware words.")
                        passwordField("Repeat new passphrase", "confirm", "new-password")
                        p("muted small") {
                            +"Everything is re-encrypted with a new key and the local backups are deleted, so the old passphrase opens nothing here any more. "
                            +"Backups you downloaded earlier still open with the old passphrase."
                        }
                        div("btn-row") { submit("Change passphrase") }
                    }
                }
            }

            div("columns") {
                card("Backup") {
                    p("muted") { +"Download the encrypted vault. It can only be opened with the passphrase and is restored on the setup page of a fresh installation." }
                    linkButton("/settings/backup", "Download encrypted backup")
                }

                card("Seal vault", "danger") {
                    p("muted") { +"Closes all SSH connections and removes keys from memory until the passphrase is entered again." }
                    postButton("/vault/seal", "Seal now", "danger", confirm = "Seal the vault? All terminals and connections close.")
                }
            }

            card("About") {
                keyValues(
                    "Unlock mode" to if (dirl.config.unlockMode == UnlockMode.KEYFILE) "key file (${dirl.config.keyFile})" else "passphrase",
                    "Identity provider" to dirl.config.oidc.issuer,
                    "Data directory" to dirl.config.dataDir,
                    "Session lifetime" to "${dirl.config.session.idleTimeoutMinutes} min idle, ${dirl.config.session.maxAgeHours} h at most",
                )
                p("muted small") { +"These come from the config file, which only holds what is needed before anybody can log in." }
            }
        }
    }
}

/** Short browser description from a `User-Agent`, only to tell sessions apart. */
private fun browserLabel(userAgent: String): String {
    val browser = listOf("Firefox", "Edg", "Chrome", "Safari").firstOrNull { userAgent.contains(it) }?.let { if (it == "Edg") "Edge" else it } ?: "Browser"
    val os = listOf("Android", "iPhone", "iPad", "Windows", "Mac OS", "Linux").firstOrNull { userAgent.contains(it) } ?: ""
    return "$browser $os".trim()
}
