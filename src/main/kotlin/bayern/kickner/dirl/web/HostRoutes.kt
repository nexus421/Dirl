package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.newId
import bayern.kickner.dirl.ssh.ConnectionState
import bayern.kickner.dirl.ssh.MAX_FAILED_UNITS
import bayern.kickner.dirl.ssh.MetricsSample
import bayern.kickner.dirl.ssh.ZramUsage
import bayern.kickner.dirl.ssh.authorizedKeysLine
import bayern.kickner.dirl.ssh.describe
import bayern.kickner.dirl.ssh.normalizeSourceAddress
import bayern.kickner.dirl.ssh.resolveRoute
import bayern.kickner.dirl.vault.DEFAULT_OVERVIEW
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.OverviewMetric
import bayern.kickner.dirl.vault.VaultContent
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingContext
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.ButtonType
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.a
import kotlinx.html.button
import kotlinx.html.checkBoxInput
import kotlinx.html.code
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.h2
import kotlinx.html.hiddenInput
import kotlinx.html.label
import kotlinx.html.li
import kotlinx.html.ol
import kotlinx.html.option
import kotlinx.html.p
import kotlinx.html.select
import kotlinx.html.span
import kotlinx.html.style
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.title
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import kotnexlib.ResultOf2
import java.net.URLEncoder
import kotlin.math.roundToInt

/** Characters allowed in a user name: what `useradd` accepts, nothing a shell would interpret. */
private val usernamePattern = Regex("^[a-zA-Z0-9._][a-zA-Z0-9._-]{0,31}$")

/** Host names, IPv4 and IPv6 addresses, IPv6 without brackets. No spaces, no options for `ssh`. */
private val addressPattern = Regex("^[a-zA-Z0-9.:-]{1,253}$")

/** Tags: letters, digits and a few separators, so they are safe in URLs and readable as chips. */
private val tagPattern = Regex("^[\\p{L}\\p{N}._-]{1,32}$")

/** Reload interval of the overview in seconds while hosts are still connecting. */
const val FAST_REFRESH_SECONDS = 3

/** Fast reloads in a row at most, then the overview falls back to once a minute. */
const val MAX_FAST_REFRESHES = 10

/** Query parameter counting the fast reloads in a row. */
private const val FAST_PARAM = "wait"

/**
 * Host overview, detail page and editing.
 *
 * - `GET /?tag=` overview as rows with connection state, round trip and the latest metrics, pinned hosts on top,
 *   in the order of the vault, reloaded every minute, every
 *   [FAST_REFRESH_SECONDS] while hosts are still connecting (see [waitingForStatus]).
 * - `GET /hosts/new`, `POST /hosts` add a host.
 * - `GET /hosts/{id}` details: connection, host key, `authorized_keys` line, latest metrics, disks.
 * - `GET /hosts/{id}/edit`, `POST /hosts/{id}` edit, `POST /hosts/{id}/delete` delete.
 * - `POST /hosts/{id}/connect` resets the backoff and connects now.
 * - `POST /hosts/{id}/pin` confirms the offered host key, `POST /hosts/{id}/forget-key` removes the pin.
 * - `POST /hosts/{id}/pinned` pins a host to the top of the overview or takes it off again.
 * - `GET /hosts/arrange`, `POST /hosts/arrange` change the order of the overview.
 */
fun Route.hostRoutes(dirl: Dirl) {
    get("/") {
        val content = dirl.vault.content ?: return@get call.respondRedirect("/unlock")
        val tag = call.request.queryParameters["tag"]?.takeIf { it.isNotBlank() }
        val allTags = content.hosts.flatMap { it.tags }.distinct().sorted()
        // The order of the vault is the order of the overview, "Arrange hosts" changes it.
        val hosts = content.hosts.filter { tag == null || tag in it.tags }
        val (pinned, others) = hosts.partition { it.pinned }

        // The automatic reload carries AUTO_REFRESH_PARAM, so it does not count as activity for the idle timeout.
        // While hosts are still connecting it comes faster, at most MAX_FAST_REFRESHES times in a row: a host that
        // stays Idle for a reason nobody foresaw must not reload the page every few seconds forever.
        val fastSoFar = call.request.queryParameters[FAST_PARAM]?.toIntOrNull() ?: 0
        val fast = fastSoFar < MAX_FAST_REFRESHES && content.hosts.any { waitingForStatus(dirl, it) }
        val reloadUrl = "/?" + listOfNotNull(
            tag?.let { "tag=" + URLEncoder.encode(it, Charsets.UTF_8) },
            "$AUTO_REFRESH_PARAM=1",
            if (fast) "$FAST_PARAM=${fastSoFar + 1}" else null,
        ).joinToString("&")
        val seconds = if (fast) FAST_REFRESH_SECONDS else 60
        call.page("Hosts", call.session, Nav.HOSTS, refresh = "$seconds; url=$reloadUrl") {
            pageHeader("Hosts", if (content.hosts.isEmpty()) null else "${content.hosts.size} host(s), status refreshes every minute") {
                if (content.hosts.size > 1) linkButton("/hosts/arrange", "Arrange")
                linkButton("/hosts/new", "Add host", "primary")
            }
            if (content.hosts.isEmpty()) return@page gettingStarted(content)

            if (allTags.isNotEmpty()) div("chips") {
                style = "margin-bottom:16px"
                a(href = "/", classes = if (tag == null) "chip active" else "chip") { +"All" }
                allTags.forEach { t -> a(href = "/?tag=${URLEncoder.encode(t, Charsets.UTF_8)}", classes = if (t == tag) "chip active" else "chip") { +"#$t" } }
            }
            if (pinned.isNotEmpty()) {
                div("host-group") { span("icon icon-pin") { }; +"Pinned" }
                div("host-list") { pinned.forEach { hostRow(dirl, content, it, tag) } }
            }
            // The divider only appears when there is something to tell apart.
            if (pinned.isNotEmpty() && others.isNotEmpty()) div("host-group") { +"Other hosts" }
            if (others.isNotEmpty()) div("host-list") { others.forEach { hostRow(dirl, content, it, tag) } }
            if (hosts.isEmpty()) notice("info", "No host has this tag.")
        }
    }

    get("/hosts/new") {
        val content = dirl.vault.content ?: return@get
        call.hostFormPage(content, null, emptyList(), null)
    }

    post("/hosts") {
        val content = dirl.vault.content ?: return@post
        val form = call.receiveParameters()
        when (val parsed = parseHostForm(form, null, content)) {
            is ResultOf2.Failure -> call.hostFormPage(content, null, parsed.value, form)
            is ResultOf2.Success -> {
                dirl.vault.update { it.copy(hosts = it.hosts + parsed.value) }
                dirl.audit.record(call.session.actor, AuditAction.HOST_ADDED, parsed.value.name)
                dirl.metrics.pollNow()
                call.respondRedirect("/hosts/${parsed.value.id}?done=host-added")
            }
        }
    }

    get("/hosts/arrange") {
        val content = dirl.vault.content ?: return@get
        call.arrangePage(content.hosts, null)
    }

    post("/hosts/arrange") {
        val content = dirl.vault.content ?: return@post
        val form = call.receiveParameters()
        val order = when (val parsed = parseArrangeForm(form, content.hosts)) {
            is ResultOf2.Success -> parsed.value
            is ResultOf2.Failure -> return@post call.arrangePage(content.hosts, parsed.value)
        }
        // Applied to the hosts at this moment: one added in between keeps its place relative to the others.
        dirl.vault.update { c -> c.copy(hosts = arrangeHosts(c.hosts, order)) }
        dirl.audit.record(call.session.actor, AuditAction.HOSTS_ARRANGED, detail = "${order.size} hosts")
        call.respondRedirect("/?done=hosts-arranged")
    }

    post("/hosts/{id}/pinned") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        val pinned = form["pinned"] == "true"
        dirl.vault.update { c -> c.copy(hosts = c.hosts.map { if (it.id == host.id) it.copy(pinned = pinned) else it }) }
        dirl.audit.record(call.session.actor, AuditAction.HOST_UPDATED, host.name, if (pinned) "pinned" else "unpinned")
        // Back to the overview as it was, with its tag filter. Only a tag that exists goes into the URL.
        val tag = form["tag"]?.takeIf { t -> dirl.vault.content?.hosts?.any { t in it.tags } == true }
        call.respondRedirect(if (tag == null) "/" else "/?tag=" + URLEncoder.encode(tag, Charsets.UTF_8))
    }

    get("/hosts/{id}") {
        val (content, host) = hostOr404(dirl) ?: return@get
        val state = dirl.connections.state(host.id)
        val key = content.key(host.keyId)
        val sample = dirl.metrics.latest(host.id)
        call.page(host.name, call.session, Nav.HOSTS) {
            pageHeader(host.name, "${host.username}@${host.address}:${host.port}") {
                if (host.jumpOnly.not()) {
                    linkButton("/hosts/${host.id}/terminal", "Terminal", "primary")
                    linkButton("/hosts/${host.id}/files", "Files")
                }
                linkButton("/hosts/${host.id}/edit", "Edit")
            }
            div("stack") {
                div("columns") {
                    card {
                        div("card-header") {
                            h2 { +"Connection" }
                            statePill(state)
                        }
                        keyValues(
                            "Address" to "${host.address}:${host.port}",
                            "User" to host.username,
                            "Jump host" to (host.jumpHostId?.let { content.host(it)?.name } ?: "none, direct"),
                            "Key" to (key?.name ?: "missing"),
                            "Role" to roleOf(host, content),
                            "Tags" to host.tags.joinToString(" ") { "#$it" }.ifEmpty { "none" },
                        )
                        connectionHint(state)
                        div("btn-row") {
                            style = "margin-top:14px"
                            postButton("/hosts/${host.id}/connect", "Connect now", "sm")
                        }
                    }
                    hostKeyCard(host, state)
                }

                if (key != null) card("Access setup") {
                    p("muted") {
                        +"Put this line into ~/.ssh/authorized_keys of ${host.username} on ${host.name}. It limits what a stolen Dirl key can do on this host."
                    }
                    val restricted = content.settings.sshSourceUnrestricted.not()
                    copyBlock(authorizedKeysLine(host, key, content.hosts, content.settings.sshSourceAddress, restricted))
                    val jump = host.jumpHostId?.let { content.host(it) }
                    if (restricted.not()) p("muted small") {
                        style = "margin-top:10px"
                        +"Without from=\"...\", because Settings turn the source restriction off. The key then works from anywhere that reaches the SSH port of ${host.name}."
                    }
                    if (restricted && jump != null && jump.sourceAddressForTargets == null) p("muted small") {
                        style = "margin-top:10px"
                        +"${host.name} sees the connection coming from ${jump.name}, not from Dirl. Set \"Address seen by hosts behind it\" on ${jump.name} to fill in from=\"...\"."
                    }
                    if (restricted && jump == null && content.settings.sshSourceAddress == null) p("muted small") {
                        style = "margin-top:10px"
                        +"Set Dirl's source address under Settings to fill in from=\"...\"."
                    }
                }

                card {
                    div("card-header") {
                        h2 { +"Status" }
                        if (sample != null) span("muted small") { +"updated ${formatTimestamp(sample.time)}" }
                    }
                    if (host.jumpOnly) p("muted") { +"Pure jump host: no commands run there, so there are no metrics. The connection state above shows whether it is reachable." }
                    else if (sample == null) p("muted") { +"No metrics yet. They arrive a few seconds after the host is connected." }
                    else metricsSection(sample)
                }

                card("Delete host", "danger") {
                    p("muted") { +"Removes the host and its pinned host key from Dirl. Nothing changes on the server." }
                    postButton("/hosts/${host.id}/delete", "Delete ${host.name}", "danger", confirm = "Delete ${host.name}?")
                }
            }
        }
    }

    get("/hosts/{id}/edit") {
        val (content, host) = hostOr404(dirl) ?: return@get
        call.hostFormPage(content, host, emptyList(), null)
    }

    post("/hosts/{id}") {
        val (content, host) = hostOr404(dirl) ?: return@post
        val form = call.receiveParameters()
        when (val parsed = parseHostForm(form, host, content)) {
            is ResultOf2.Failure -> call.hostFormPage(content, host, parsed.value, form)
            is ResultOf2.Success -> {
                dirl.vault.update { c -> c.copy(hosts = c.hosts.map { if (it.id == host.id) parsed.value else it }) }
                dirl.connections.drop(host.id)
                dirl.audit.record(call.session.actor, AuditAction.HOST_UPDATED, parsed.value.name)
                dirl.metrics.pollNow()
                call.respondRedirect("/hosts/${host.id}?done=host-saved")
            }
        }
    }

    post("/hosts/{id}/delete") {
        val (content, host) = hostOr404(dirl) ?: return@post
        val dependents = content.hosts.filter { it.jumpHostId == host.id }
        if (dependents.isNotEmpty()) return@post call.page("Cannot delete", call.session, Nav.HOSTS, status = HttpStatusCode.Conflict) {
            pageHeader("Cannot delete ${host.name}")
            notice("error", "${host.name} is the jump host of ${dependents.joinToString { it.name }}. Change those hosts first.")
            linkButton("/hosts/${host.id}", "Back")
        }
        dirl.connections.drop(host.id)
        dirl.vault.update { c -> c.copy(hosts = c.hosts.filterNot { it.id == host.id }) }
        dirl.metrics.forget(host.id)
        dirl.audit.record(call.session.actor, AuditAction.HOST_DELETED, host.name)
        call.respondRedirect("/?done=host-deleted")
    }

    post("/hosts/{id}/connect") {
        val (_, host) = hostOr404(dirl) ?: return@post
        dirl.connections.reset(host.id)
        dirl.connections.connection(host.id)
        dirl.metrics.pollNow()
        call.respondRedirect("/hosts/${host.id}")
    }

    post("/hosts/{id}/pin") {
        val (_, host) = hostOr404(dirl) ?: return@post
        val fingerprint = call.receiveParameters()["fingerprint"].orEmpty()
        val pinned = dirl.connections.pinHostKey(host.id, fingerprint, call.session.actor)
        if (pinned.not()) return@post call.page("Host key not pinned", call.session, Nav.HOSTS, status = HttpStatusCode.Conflict) {
            pageHeader("Host key not pinned")
            notice("error", "The server now offers a different key than the one you confirmed. Check the host and try again.")
            linkButton("/hosts/${host.id}", "Back")
        }
        dirl.connections.connection(host.id)
        dirl.metrics.pollNow()
        call.respondRedirect("/hosts/${host.id}?done=pinned")
    }

    post("/hosts/{id}/forget-key") {
        val (_, host) = hostOr404(dirl) ?: return@post
        dirl.vault.update { c -> c.copy(hosts = c.hosts.map { if (it.id == host.id) it.copy(pinnedHostKey = null) else it }) }
        dirl.connections.drop(host.id)
        dirl.audit.record(call.session.actor, AuditAction.HOST_UPDATED, host.name, "host key pin removed")
        call.respondRedirect("/hosts/${host.id}?done=pin-removed")
    }
}

/**
 * Looks up the host from the `{id}` path parameter, responding 404 if it does not exist. The page is the general
 * "Page not found" from [installErrorPages], which replaces every 404 response anyway.
 *
 * @return the content and the host, or `null` after the 404 was sent.
 */
suspend fun RoutingContext.hostOr404(dirl: Dirl): Pair<VaultContent, Host>? {
    val content = dirl.vault.content
    val host = content?.host(call.parameters["id"].orEmpty())
    if (content == null || host == null) {
        call.respond(HttpStatusCode.NotFound)
        return null
    }
    return content to host
}

/**
 * Builds a host from the form fields and validates it, including the route through the jump hosts. A change that
 * breaks the route of another host that worked before, e.g. a chain behind this host getting too long, is refused.
 *
 * Changing address, port or jump host drops the pinned host key: it is a different endpoint, and a stale pin
 * would only show up as a scary mismatch.
 *
 * @param existing The host being edited, `null` for a new host.
 * @return the host, or all problems at once.
 */
fun parseHostForm(form: Parameters, existing: Host?, content: VaultContent): ResultOf2<Host, List<String>> {
    val errors = mutableListOf<String>()
    val name = form["name"].orEmpty().trim()
    // "[fd00::5]" as in URLs works for direct connections, but a jump host cannot resolve it. Stored without brackets.
    val address = form["address"].orEmpty().trim().removeSurrounding("[", "]")
    val port = form["port"]?.trim()?.toIntOrNull()
    val username = form["username"].orEmpty().trim()
    val keyId = form["keyId"].orEmpty()
    val jumpHostId = form["jumpHostId"].orEmpty().ifBlank { null }
    val tags = form["tags"].orEmpty().split(',', ' ').map { it.trim().removePrefix("#") }.filter { it.isNotEmpty() }.distinct()
    val sourceAddressForTargets = when (val result = normalizeSourceAddress(form["sourceAddressForTargets"].orEmpty())) {
        is ResultOf2.Success -> result.value
        is ResultOf2.Failure -> null.also { errors += "Address seen by hosts behind it: ${result.value}" }
    }
    // The choice only counts when the form showed it, any other form keeps what the host had. Unknown values are
    // dropped, nothing ticked is a valid choice.
    val overview = if (form["overviewShown"] == "1") {
        val ticked = form.getAll("overview").orEmpty().toSet()
        OverviewMetric.entries.filter { it.name in ticked }.toSet()
    } else existing?.overview ?: DEFAULT_OVERVIEW

    if (name.isEmpty() || name.length > 64) errors += "Name is required (at most 64 characters)"
    if (addressPattern.matches(address).not()) errors += "Address must be a host name or an IP address"
    if (port == null || port !in 1..65535) errors += "Port must be between 1 and 65535"
    if (usernamePattern.matches(username).not()) errors += "User name contains invalid characters"
    if (content.key(keyId) == null) errors += "Choose a key, or create one under Keys first"
    if (jumpHostId != null && content.host(jumpHostId) == null) errors += "Unknown jump host"
    if (tags.any { tagPattern.matches(it).not() }) errors += "Tags may only contain letters, digits, dots, dashes and underscores"
    if (errors.isNotEmpty()) return ResultOf2.Failure(errors)

    val endpointChanged = existing != null &&
        (existing.address != address || existing.port != port || existing.jumpHostId != jumpHostId)
    val host = Host(
        id = existing?.id ?: newId(),
        name = name,
        address = address,
        port = port!!,
        username = username,
        keyId = keyId,
        jumpHostId = jumpHostId,
        tags = tags,
        jumpOnly = form["jumpOnly"] == "on",
        pinnedHostKey = if (endpointChanged) null else existing?.pinnedHostKey,
        sourceAddressForTargets = sourceAddressForTargets,
        pinned = existing?.pinned ?: false,
        overview = overview,
    )

    val candidate = content.copy(hosts = content.hosts.filterNot { it.id == host.id } + host)
    val route = resolveRoute(candidate, host.id)
    if (route is ResultOf2.Failure) return ResultOf2.Failure(listOf(route.value))
    // The hosts behind this one get a longer chain as well. Only routes that worked before count, an older broken
    // one must not block saving an unrelated host.
    val broken = content.hosts.firstNotNullOfOrNull { other ->
        if (other.id == host.id || resolveRoute(content, other.id) is ResultOf2.Failure) null
        else (resolveRoute(candidate, other.id) as? ResultOf2.Failure)?.value
    }
    return if (broken == null) ResultOf2.Success(host) else ResultOf2.Failure(listOf("Saving would break another host: $broken"))
}

private fun FlowContent.gettingStarted(content: VaultContent) = card {
    div("empty") {
        h2 { +"No hosts yet" }
        ol {
            li { +"Create or import a key that exists only for Dirl." }
            li { +"Add a host and choose that key." }
            li { +"Put the shown authorized_keys line on the server." }
            li { +"Connect and confirm the host key fingerprint." }
        }
        div("btn-row") {
            style = "justify-content:center"
            if (content.keys.isEmpty()) linkButton("/keys", "Create a key", "primary")
            else linkButton("/hosts/new", "Add host", "primary")
        }
    }
}

/**
 * How a host row looks: the color of its status bar and its icon.
 *
 * @property css The class of the row and the name of the icon.
 */
enum class Health(val css: String) { OK("ok"), WARN("warn"), ERROR("error"), PENDING("pending") }

/**
 * The health of a host row. Red without a connection, grey while connecting, yellow when [attention] is needed (a
 * warning or a critical value), the round trip is [SLOW_ROUND_TRIP_MILLIS] or more, or a host key waits for its
 * confirmation. Green otherwise.
 */
fun healthOf(state: ConnectionState, attention: Boolean, latency: Double?): Health = when (state) {
    is ConnectionState.Failed, is ConnectionState.AuthFailed, is ConnectionState.Stopped, is ConnectionState.HostKeyMismatch -> Health.ERROR
    ConnectionState.Idle, ConnectionState.Connecting -> Health.PENDING
    is ConnectionState.HostKeyUnknown -> Health.WARN
    is ConnectionState.Connected -> if (attention || (latency ?: 0.0) >= SLOW_ROUND_TRIP_MILLIS) Health.WARN else Health.OK
}

/** Round trip in milliseconds from which the ping turns yellow. */
const val SLOW_ROUND_TRIP_MILLIS = 100.0

/** Metric value in percent from which a host row turns yellow. */
private const val CRITICAL_PERCENT = 90.0

/**
 * One row of the overview: status bar with pin button, name with warnings and tags, bars, further values, round trip
 * and actions. The name is the link to the host page, its click area covers the whole row (CSS), the buttons lie on
 * top of it.
 *
 * The color comes from [healthOf]: a warning chosen for the overview or a bar at [CRITICAL_PERCENT] or more needs
 * attention.
 */
private fun FlowContent.hostRow(dirl: Dirl, content: VaultContent, host: Host, tag: String?) {
    val state = dirl.connections.state(host.id)
    val sample = dirl.metrics.latest(host.id)?.takeIf { host.jumpOnly.not() }
    val latency = dirl.metrics.latencyMillis(host.id)?.takeIf { state is ConnectionState.Connected }
    val warnings = buildList {
        when (state) {
            is ConnectionState.AuthFailed, is ConnectionState.Stopped, is ConnectionState.HostKeyMismatch -> add("error" to stateLabel(state))
            is ConnectionState.HostKeyUnknown -> add("warn" to stateLabel(state))
            else -> Unit
        }
        if (sample != null) overviewWarnings(host.overview, sample).forEach { add("warn" to it) }
    }
    val critical = sample != null && overviewPercents(host.overview, sample).any { it >= CRITICAL_PERCENT }
    val health = healthOf(state, warnings.isNotEmpty() || critical, latency)

    div("host-row ${health.css}") {
        div("host-status") {
            span("icon status-icon icon-${health.css}") {
                attributes["role"] = "img"
                attributes["aria-label"] = stateLabel(state)
                title = stateLabel(state)
            }
            form(action = "/hosts/${host.id}/pinned", method = FormMethod.post, classes = "pin-form") {
                hiddenInput(name = "pinned") { value = host.pinned.not().toString() }
                if (tag != null) hiddenInput(name = "tag") { value = tag }
                button(type = ButtonType.submit, classes = if (host.pinned) "pin-toggle on" else "pin-toggle") {
                    val label = if (host.pinned) "Unpin ${host.name}" else "Pin ${host.name} to the top"
                    title = label
                    attributes["aria-label"] = label
                    span("icon icon-pin") { }
                }
            }
        }
        div("host-main") {
            a(href = "/hosts/${host.id}", classes = "host-name") { +host.name }
            if (warnings.isNotEmpty()) div("host-warnings") { warnings.forEach { (kind, text) -> span("pill $kind") { +text } } }
            if (host.tags.isNotEmpty() || host.jumpOnly) div("host-tags") {
                if (host.jumpOnly) span("tag plain") { +"jump host" }
                host.tags.forEach { t -> span("tag") { style = "--tag-h:${tagHue(t)}"; +t } }
            }
        }
        div("host-meters") { if (sample != null) overviewBars(host.overview, sample) else span("muted") { +"–" } }
        div("host-facts") {
            val facts = when {
                host.jumpOnly -> listOf(content.hosts.filter { it.jumpHostId == host.id }.joinToString { it.name }.let { if (it.isEmpty()) "Jump host, nothing behind it yet" else "Jump host for $it" })
                state is ConnectionState.Failed -> listOf(describe(state), "Next try ${formatTimestamp(state.retryAt)}")
                state is ConnectionState.AuthFailed -> listOf("Next try ${formatTimestamp(state.retryAt)}")
                sample != null -> overviewFacts(host.overview, sample)
                else -> emptyList()
            }
            if (facts.isNotEmpty()) div("facts") { facts.forEach { span { +it } } }
        }
        pingCell(state, latency)
        div("host-actions") {
            when {
                health == Health.ERROR -> postButton("/hosts/${host.id}/connect", "Connect now", "sm")
                state is ConnectionState.HostKeyUnknown -> linkButton("/hosts/${host.id}", "Confirm key", "primary sm")
                host.jumpOnly -> Unit
                else -> {
                    linkButton("/hosts/${host.id}/terminal", "Terminal", "primary sm")
                    linkButton("/hosts/${host.id}/files", "Files", "sm")
                }
            }
        }
    }
}

/** Signal bars and the round trip, green below [SLOW_ROUND_TRIP_MILLIS], then yellow, red without connection. */
private fun FlowContent.pingCell(state: ConnectionState, latency: Double?) {
    val (level, kind, text) = when {
        latency != null -> Triple(
            when {
                latency < 50 -> 4
                latency < SLOW_ROUND_TRIP_MILLIS -> 3
                latency < 200 -> 2
                else -> 1
            },
            if (latency < SLOW_ROUND_TRIP_MILLIS) "ok" else "warn",
            roundTripText(latency),
        )
        // Reachable, only the key is not confirmed yet.
        state is ConnectionState.Connected || state is ConnectionState.HostKeyUnknown -> Triple(0, "", "–")
        state == ConnectionState.Idle || state == ConnectionState.Connecting -> Triple(0, "", "connecting")
        else -> Triple(0, "error", "offline")
    }
    div("host-ping $kind".trim()) {
        title = "Round trip from Dirl to the host over SSH"
        span("signal lvl-$level") { repeat(4) { span { } } }
        span("ms") { +text }
    }
}

/** A round trip for the overview: `<1 ms` on a local network, whole milliseconds from 1 ms on. */
fun roundTripText(millis: Double): String = if (millis < 1) "<1 ms" else "${millis.roundToInt()} ms"

/**
 * A stable hue for [tag], so the same tag has the same color everywhere without anybody choosing one.
 * `String.hashCode` is specified, so the color does not change between versions or machines.
 */
fun tagHue(tag: String): Int = Math.floorMod(tag.lowercase().hashCode(), 360)

/** The overview warnings of [sample] that [chosen] asks for. */
private fun overviewWarnings(chosen: Set<OverviewMetric>, sample: MetricsSample): List<String> = buildList {
    val raw = sample.raw
    // An unknown reboot status is not shown: it is unknown in every container, it would be on every such row.
    // The host page says it.
    if (OverviewMetric.REBOOT in chosen && raw.reboot?.needed == true) add("Reboot needed")
    val failed = raw.failedUnits.orEmpty()
    if (OverviewMetric.FAILED_SERVICES in chosen && failed.isNotEmpty()) add(
        when {
            failed.size >= MAX_FAILED_UNITS -> "At least $MAX_FAILED_UNITS failed services"
            failed.size == 1 -> "1 failed service"
            else -> "${failed.size} failed services"
        },
    )
}

/** The percentages the bars of [chosen] show, to tell whether one is critical. */
private fun overviewPercents(chosen: Set<OverviewMetric>, sample: MetricsSample): List<Double> = buildList {
    val disks = sample.disks.filter { it.totalKiB > 0 }.map { it.usedKiB * 100.0 / it.totalKiB }
    if (OverviewMetric.CPU in chosen) sample.cpuPercent?.let { add(it) }
    if (OverviewMetric.RAM in chosen) percentOf(sample.memUsedKiB, sample.memTotalKiB)?.let { add(it) }
    if (OverviewMetric.SWAP in chosen) percentOf(sample.swapUsedKiB, sample.swapTotalKiB)?.let { add(it) }
    if (OverviewMetric.DISK in chosen || OverviewMetric.DISKS in chosen) disks.maxOrNull()?.let { add(it) }
}

/** The bars of [sample] that [chosen] asks for. */
private fun FlowContent.overviewBars(chosen: Set<OverviewMetric>, sample: MetricsSample) {
    val bars = setOf(OverviewMetric.CPU, OverviewMetric.RAM, OverviewMetric.SWAP, OverviewMetric.DISK, OverviewMetric.DISKS)
    val disks = sample.disks.filter { it.totalKiB > 0 }
    // With mount points as labels every bar of the row gets the wide label column, so the bars line up.
    val wide = OverviewMetric.DISKS in chosen
    if (chosen.any { it in bars }) div("meters") {
        if (OverviewMetric.CPU in chosen) meter("CPU", sample.cpuPercent, wide)
        if (OverviewMetric.RAM in chosen) meter("RAM", percentOf(sample.memUsedKiB, sample.memTotalKiB), wide)
        if (OverviewMetric.SWAP in chosen && sample.swapTotalKiB > 0) meter("Swap", percentOf(sample.swapUsedKiB, sample.swapTotalKiB), wide)
        if (OverviewMetric.DISK in chosen) {
            val fullest = disks.maxByOrNull { it.usedKiB.toDouble() / it.totalKiB }
            meter("Disk", fullest?.let { percentOf(it.usedKiB, it.totalKiB) }, wide)
        }
        if (wide) disks.forEach { meter(it.mount, percentOf(it.usedKiB, it.totalKiB), wide = true) }
    }
}

/** The short facts of [sample] that [chosen] asks for. */
private fun overviewFacts(chosen: Set<OverviewMetric>, sample: MetricsSample): List<String> = buildList {
    val raw = sample.raw
    if (OverviewMetric.SWAP in chosen && sample.swapTotalKiB == 0L) add("No swap")
    if (OverviewMetric.LOAD in chosen) add("Load ${loads(raw.load1, raw.load5, raw.load15, " ")}" + (raw.cores?.let { " · ${cores(it)}" } ?: ""))
    if (OverviewMetric.UPTIME in chosen) add("Up ${uptime(sample.uptimeSeconds)}")
    if (OverviewMetric.FAILED_SERVICES in chosen && raw.failedUnits == null) add("Services unknown")
    if (OverviewMetric.ZRAM in chosen) add(
        when (val z = raw.zram) {
            null -> "No zram"
            else -> if (z.origBytes < ZRAM_NEARLY_EMPTY_BYTES) "zram on, nearly empty"
            else "zram ${bytes(z.origBytes)} in ${bytes(z.memUsedBytes)} RAM" + (zramFactor(z)?.let { " ($it)" } ?: "")
        },
    )
    if (OverviewMetric.SYSTEM in chosen) listOfNotNull(raw.osName, raw.kernel).takeIf { it.isNotEmpty() }?.let { add(it.joinToString(" · ")) }
    if (OverviewMetric.USERS in chosen) raw.loggedInUsers?.let { add("$it logged in") }
}

/** A bar with [label]. [wide] leaves room for a mount point as label, cut with an ellipsis and complete as tooltip. */
private fun FlowContent.meter(label: String, percent: Double?, wide: Boolean = false) = div(if (wide) "meter wide" else "meter") {
    span { if (wide) title = label; +label }
    meterBar(percent, unknown = "...")
}

/** The connection state in a few words, for the status icon and the warnings of a row. */
private fun stateLabel(state: ConnectionState): String = when (state) {
    is ConnectionState.Connected -> "online"
    ConnectionState.Idle -> "idle"
    ConnectionState.Connecting -> "connecting"
    is ConnectionState.Failed -> "unreachable"
    is ConnectionState.AuthFailed -> "login rejected"
    is ConnectionState.Stopped -> "stopped"
    is ConnectionState.HostKeyUnknown -> "confirm host key"
    is ConnectionState.HostKeyMismatch -> "host key changed"
}

private fun FlowContent.statePill(state: ConnectionState) = pill(
    when (state) {
        is ConnectionState.Connected -> "ok"
        ConnectionState.Idle, ConnectionState.Connecting -> ""
        is ConnectionState.Failed, is ConnectionState.AuthFailed, is ConnectionState.HostKeyUnknown -> "warn"
        is ConnectionState.Stopped, is ConnectionState.HostKeyMismatch -> "error"
    },
    stateLabel(state),
)

private fun FlowContent.connectionHint(state: ConnectionState) {
    val text = when (state) {
        is ConnectionState.Failed -> "${describe(state)}. Next automatic attempt ${formatTimestamp(state.retryAt)}."
        is ConnectionState.AuthFailed -> "The server rejected the key. Check the authorized_keys line. Next attempt ${formatTimestamp(state.retryAt)}."
        is ConnectionState.Stopped -> "${describe(state)}. Fix the cause, then click Connect now."
        else -> return
    }
    p("muted small") {
        style = "margin:12px 0 0"
        +text
    }
}

private fun FlowContent.hostKeyCard(host: Host, state: ConnectionState) = card {
    div("card-header") {
        h2 { +"Host key" }
        when {
            state is ConnectionState.HostKeyMismatch -> pill("error", "changed")
            state is ConnectionState.HostKeyUnknown -> pill("warn", "unconfirmed")
            host.pinnedHostKey != null -> pill("ok", "pinned")
            else -> pill("", "not seen yet")
        }
    }
    when {
        state is ConnectionState.HostKeyMismatch -> {
            notice("error", "The host key changed. This can be a reinstalled server or a man-in-the-middle attack. Dirl will not connect.")
            keyValues("Pinned" to state.expected, "Offered now" to state.actual)
            p("muted small") {
                style = "margin-top:12px"
                +"Check on the server with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub. Only if the new key is legitimate, remove the pin and confirm the new one."
            }
            postButton("/hosts/${host.id}/forget-key", "Remove pin", "danger sm", confirm = "Remove the pinned host key of ${host.name}?")
        }

        state is ConnectionState.HostKeyUnknown -> {
            p { +"First connection. Compare this fingerprint with the server before you trust it:" }
            p { code("inline") { +"${state.keyType} ${state.fingerprint}" } }
            p("muted small") { +"On the server: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" }
            postButton("/hosts/${host.id}/pin", "Fingerprint matches, trust it", "primary", hidden = mapOf("fingerprint" to state.fingerprint))
        }

        host.pinnedHostKey != null -> {
            val pin = host.pinnedHostKey
            keyValues("Type" to pin.keyType, "Fingerprint" to pin.fingerprint, "Pinned" to formatTimestamp(pin.pinnedAt))
            div("btn-row") {
                style = "margin-top:14px"
                postButton("/hosts/${host.id}/forget-key", "Remove pin", "ghost sm", confirm = "Remove the pinned host key? The next connection asks again.")
            }
        }

        else -> p("muted") { +"Connect once to see the fingerprint. Dirl only connects after you confirmed it." }
    }
}

private fun FlowContent.metricsSection(sample: MetricsSample) {
    val raw = sample.raw
    keyValues(
        "CPU" to (sample.cpuPercent?.let { "${it.roundToInt()}%" } ?: "unknown"),
        "Load" to "${loads(raw.load1, raw.load5, raw.load15, " / ")} (1, 5, 15 min)" + (raw.cores?.let { ", ${cores(it)}" } ?: ""),
        "RAM" to "${pct(sample.memUsedKiB, sample.memTotalKiB)} of ${gib(sample.memTotalKiB)}",
        "Swap" to if (sample.swapTotalKiB == 0L) "none" else "${pct(sample.swapUsedKiB, sample.swapTotalKiB)} of ${gib(sample.swapTotalKiB)}",
        "zram" to when (val z = raw.zram) {
            null -> "none"
            else -> if (z.origBytes < ZRAM_NEARLY_EMPTY_BYTES) "on, nearly empty (${bytes(z.origBytes)} stored)"
            else "${bytes(z.origBytes)} stored, ${bytes(z.comprBytes)} compressed, ${bytes(z.memUsedBytes)} RAM used" + (zramFactor(z)?.let { " ($it)" } ?: "")
        },
        "Uptime" to uptime(sample.uptimeSeconds),
        "Reboot needed" to when {
            raw.reboot == null -> "unknown, no kernel under /boot (for example a container)"
            raw.reboot.needed.not() -> "no"
            raw.reboot.newerKernel != null -> "yes, ${raw.kernel} runs, ${raw.reboot.newerKernel} is installed"
            else -> "yes, the system asks for it (/run/reboot-required)"
        },
        "Failed services" to when {
            raw.failedUnits == null -> "unknown, no systemd"
            raw.failedUnits.isEmpty() -> "none"
            raw.failedUnits.size >= MAX_FAILED_UNITS -> "at least $MAX_FAILED_UNITS: ${raw.failedUnits.joinToString()}"
            else -> raw.failedUnits.joinToString()
        },
        "System" to (raw.osName ?: "unknown"),
        "Kernel" to (raw.kernel ?: "unknown"),
        "Logged in users" to (raw.loggedInUsers?.let { "$it (logins with a terminal, Dirl's own terminals count too)" } ?: "unknown"),
    )
    if (sample.disks.isNotEmpty()) div("table-wrap") {
        style = "margin-top:16px"
        table {
            thead { tr { th { +"Mount" }; th(classes = "hide-sm") { +"Type" }; th { +"Used" }; th { +"Size" } } }
            tbody {
                sample.disks.forEach { d ->
                    tr {
                        td("mono") { +d.mount }
                        td("muted hide-sm") { +d.fsType }
                        td { div("meter") { style = "grid-template-columns:1fr 46px"; meterBar(percentOf(d.usedKiB, d.totalKiB)) } }
                        td("num") { +gib(d.totalKiB) }
                    }
                }
            }
        }
    }
}

/** The bar of a meter and its value, [unknown] instead of the value while it is not known. */
private fun FlowContent.meterBar(percent: Double?, unknown: String = "") {
    val level = when {
        percent == null -> ""
        percent >= 90 -> " critical"
        percent >= 75 -> " high"
        else -> ""
    }
    // --p scales the fixed green to red gradient, so the end of the bar shows the color of its value.
    val rounded = (percent ?: 0.0).roundToInt().coerceIn(0, 100)
    div("bar$level") { span { style = "--v:$rounded%;--p:${rounded.coerceAtLeast(1)}" } }
    span("val") { +(percent?.let { "${it.roundToInt()}%" } ?: unknown) }
}

private suspend fun ApplicationCall.hostFormPage(content: VaultContent, host: Host?, errors: List<String>, form: Parameters?) {
    val value = { name: String, fallback: String -> form?.get(name) ?: fallback }
    val title = if (host == null) "Add host" else "Edit ${host.name}"
    page(title, session, Nav.HOSTS, status = if (errors.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title)
        errors.forEach { notice("error", it) }
        if (content.keys.isEmpty()) notice("warn", "There is no key yet. Create one under Keys first.")
        card {
            form(action = if (host == null) "/hosts" else "/hosts/${host.id}", method = FormMethod.post, classes = "form") {
                div("grid-2") {
                    textField("Name", "name", value("name", host?.name.orEmpty()), placeholder = "web-01")
                    textField("Tags", "tags", value("tags", host?.tags?.joinToString(" ").orEmpty()), hint = "Separated by spaces, e.g. prod web", required = false)
                }
                div("grid-2") {
                    textField("Address", "address", value("address", host?.address.orEmpty()), hint = "Host name or IP, as seen from Dirl or from the jump host.", placeholder = "10.0.0.5")
                    textField("Port", "port", value("port", (host?.port ?: 22).toString()))
                }
                div("grid-2") {
                    textField("User", "username", value("username", host?.username.orEmpty()), placeholder = "root")
                    label("field") {
                        span { +"Key" }
                        select {
                            name = "keyId"
                            attributes["aria-label"] = "Key"
                            content.keys.forEach { key -> option { this.value = key.id; selected = key.id == value("keyId", host?.keyId.orEmpty()); +key.name } }
                        }
                    }
                }
                label("field") {
                    span { +"Jump host" }
                    select {
                        name = "jumpHostId"
                        attributes["aria-label"] = "Jump host"
                        option { this.value = ""; +"None, connect directly" }
                        content.hosts.filter { it.id != host?.id }.forEach { other ->
                            option { this.value = other.id; selected = other.id == value("jumpHostId", host?.jumpHostId.orEmpty()); +other.name }
                        }
                    }
                    span("hint") { +"At most two jump hosts in a row." }
                }
                checkField(
                    "Jump host only: no terminal, no files, no metrics. Its authorized_keys line then only forwards to the hosts behind it. Unix socket forwarding needs a server setting, see the security docs",
                    "jumpOnly", (form?.get("jumpOnly") ?: if (host?.jumpOnly == true) "on" else "") == "on",
                )
                textField(
                    "Address seen by hosts behind it", "sourceAddressForTargets", value("sourceAddressForTargets", host?.sourceAddressForTargets.orEmpty()),
                    hint = "Only for jump hosts. The address the hosts behind this one see it connecting from, often its address in their network. Fills from=\"...\" in their authorized_keys lines. " +
                        "Several addresses or CIDR ranges are separated by commas. Not used while Settings turn the source restriction off.",
                    required = false, placeholder = "e.g. 10.0.0.1",
                )
                div("field") {
                    span { +"Shown in the overview" }
                    // Marks that this form carries the choice, an unticked box is not sent at all.
                    hiddenInput(name = "overviewShown") { this.value = "1" }
                    val ticked = if (form?.get("overviewShown") == "1") form.getAll("overview").orEmpty().toSet()
                    else (host?.overview ?: DEFAULT_OVERVIEW).map { it.name }.toSet()
                    div("checks") {
                        OverviewMetric.entries.forEach { metric ->
                            label("check") {
                                checkBoxInput(name = "overview") { this.value = metric.name; checked = metric.name in ticked }
                                span { +metric.label() }
                            }
                        }
                    }
                    span("hint") { +"Dirl asks every host for all values once a minute while Dirl is used, this only decides what its card shows. The host page shows everything. Jump hosts only have no values." }
                }
                if (host?.pinnedHostKey != null) p("muted small") { +"Changing address, port or jump host removes the pinned host key." }
                div("btn-row") {
                    submit("Save")
                    linkButton(if (host == null) "/" else "/hosts/${host.id}", "Cancel", "ghost")
                }
            }
        }
    }
}

/**
 * True while [host] is on its way to a status: not tried yet, connecting, or connected but not polled yet. Hosts that
 * failed, were stopped or wait for a host key confirmation are not waiting, they stay like that until somebody acts.
 */
fun waitingForStatus(dirl: Dirl, host: Host): Boolean = when (dirl.connections.state(host.id)) {
    ConnectionState.Idle, ConnectionState.Connecting -> true
    is ConnectionState.Connected -> host.jumpOnly.not() && dirl.metrics.polled(host.id).not()
    else -> false
}

/** Label of a choice in the host form. */
private fun OverviewMetric.label(): String = when (this) {
    OverviewMetric.CPU -> "CPU"
    OverviewMetric.RAM -> "RAM"
    OverviewMetric.SWAP -> "Swap"
    OverviewMetric.DISK -> "Fullest disk"
    OverviewMetric.DISKS -> "All disks"
    OverviewMetric.LOAD -> "Load and cores"
    OverviewMetric.UPTIME -> "Uptime"
    OverviewMetric.REBOOT -> "Reboot needed"
    OverviewMetric.FAILED_SERVICES -> "Failed services"
    OverviewMetric.ZRAM -> "zram"
    OverviewMetric.SYSTEM -> "System and kernel"
    OverviewMetric.USERS -> "Logged in users"
}

/** Human readable role of [host] in the jump host chain. */
private fun roleOf(host: Host, content: VaultContent): String {
    val behind = content.hosts.filter { it.jumpHostId == host.id }.map { it.name }
    return when {
        host.jumpOnly && behind.isEmpty() -> "jump host only, nothing behind it yet"
        host.jumpOnly -> "jump host only, for ${behind.joinToString()}"
        behind.isNotEmpty() -> "server and jump host for ${behind.joinToString()}"
        else -> "server"
    }
}

private fun percentOf(used: Long, total: Long): Double? = if (total <= 0) null else used * 100.0 / total

private fun pct(used: Long, total: Long): String = percentOf(used, total)?.let { "${it.roundToInt()}%" }.orEmpty()

private fun gib(kib: Long): String = "%.1f GiB".format(kib / 1024.0 / 1024.0)

private fun loads(one: Double, five: Double, fifteen: Double, separator: String) =
    listOf(one, five, fifteen).joinToString(separator) { "%.2f".format(it) }

private fun cores(count: Int) = if (count == 1) "1 core" else "$count cores"

/** Bytes as KiB below 1 MiB, as MiB below 1 GiB, as GiB above. */
private fun bytes(count: Long): String = when {
    count < 1024L * 1024 -> "%.0f KiB".format(count / 1024.0)
    count < 1024L * 1024 * 1024 -> "%.0f MiB".format(count / 1024.0 / 1024.0)
    else -> "%.1f GiB".format(count / 1024.0 / 1024.0 / 1024.0)
}

/**
 * Below this much stored data zram counts as nearly empty. A few swapped pages are mostly zero filled ones, which
 * zram keeps without compressing (they count as stored, not as compressed), so their factor says nothing.
 */
private const val ZRAM_NEARLY_EMPTY_BYTES = 1024L * 1024

/**
 * How much RAM zram really saves, e.g. `5.3x`: stored data against the RAM it takes, overhead included. Not against
 * the compressed size, zero filled pages would inflate that. `null` if zram takes no RAM at all.
 */
private fun zramFactor(zram: ZramUsage): String? =
    if (zram.memUsedBytes <= 0) null else "%.1fx".format(zram.origBytes.toDouble() / zram.memUsedBytes)

private fun uptime(seconds: Double): String {
    val days = (seconds / 86400).toInt()
    val hours = ((seconds % 86400) / 3600).toInt()
    return if (days > 0) "$days d $hours h" else "$hours h ${((seconds % 3600) / 60).toInt()} min"
}
