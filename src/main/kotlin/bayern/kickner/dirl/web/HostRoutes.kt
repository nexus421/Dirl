package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.formatTimestamp
import bayern.kickner.dirl.newId
import bayern.kickner.dirl.ssh.ConnectionState
import bayern.kickner.dirl.ssh.MetricsSample
import bayern.kickner.dirl.ssh.SOURCE_ADDRESS_PATTERN
import bayern.kickner.dirl.ssh.authorizedKeysLine
import bayern.kickner.dirl.ssh.describe
import bayern.kickner.dirl.ssh.resolveRoute
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.VaultContent
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingContext
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.a
import kotlinx.html.code
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.h2
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
 * - `GET /?tag=` overview as cards with connection state and the latest metrics, reloaded every minute, every
 *   [FAST_REFRESH_SECONDS] while hosts are still connecting (see [waitingForStatus]).
 * - `GET /hosts/new`, `POST /hosts` add a host.
 * - `GET /hosts/{id}` details: connection, host key, `authorized_keys` line, latest metrics, disks.
 * - `GET /hosts/{id}/edit`, `POST /hosts/{id}` edit, `POST /hosts/{id}/delete` delete.
 * - `POST /hosts/{id}/connect` resets the backoff and connects now.
 * - `POST /hosts/{id}/pin` confirms the offered host key, `POST /hosts/{id}/forget-key` removes the pin.
 */
fun Route.hostRoutes(dirl: Dirl) {
    get("/") {
        val content = dirl.vault.content ?: return@get call.respondRedirect("/unlock")
        val tag = call.request.queryParameters["tag"]?.takeIf { it.isNotBlank() }
        val allTags = content.hosts.flatMap { it.tags }.distinct().sorted()
        val hosts = content.hosts.filter { tag == null || tag in it.tags }.sortedBy { it.name.lowercase() }

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
                linkButton("/hosts/new", "Add host", "primary")
            }
            if (content.hosts.isEmpty()) return@page gettingStarted(content)

            if (allTags.isNotEmpty()) div("chips") {
                style = "margin-bottom:16px"
                a(href = "/", classes = if (tag == null) "chip active" else "chip") { +"All" }
                allTags.forEach { t -> a(href = "/?tag=${URLEncoder.encode(t, Charsets.UTF_8)}", classes = if (t == tag) "chip active" else "chip") { +"#$t" } }
            }
            div("host-grid") {
                hosts.forEach { host -> hostCard(dirl, content, host) }
            }
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
                    copyBlock(authorizedKeysLine(host, key, content.hosts, content.settings.sshSourceAddress))
                    val jump = host.jumpHostId?.let { content.host(it) }
                    if (jump != null && jump.sourceAddressForTargets == null) p("muted small") {
                        style = "margin-top:10px"
                        +"${host.name} sees the connection coming from ${jump.name}, not from Dirl. Set \"Address seen by hosts behind it\" on ${jump.name} to fill in from=\"...\"."
                    }
                    if (jump == null && content.settings.sshSourceAddress == null) p("muted small") {
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
 * Looks up the host from the `{id}` path parameter, responding 404 if it does not exist.
 *
 * @return the content and the host, or `null` after the 404 was sent.
 */
suspend fun RoutingContext.hostOr404(dirl: Dirl): Pair<VaultContent, Host>? {
    val content = dirl.vault.content
    val host = content?.host(call.parameters["id"].orEmpty())
    if (content == null || host == null) {
        call.page("Not found", call.session, Nav.HOSTS, status = HttpStatusCode.NotFound) {
            pageHeader("Host not found")
            linkButton("/", "All hosts")
        }
        return null
    }
    return content to host
}

/**
 * Builds a host from the form fields and validates it, including the route through the jump hosts.
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
    val sourceAddressForTargets = form["sourceAddressForTargets"].orEmpty().trim().ifEmpty { null }

    if (name.isEmpty() || name.length > 64) errors += "Name is required (at most 64 characters)"
    if (addressPattern.matches(address).not()) errors += "Address must be a host name or an IP address"
    if (port == null || port !in 1..65535) errors += "Port must be between 1 and 65535"
    if (usernamePattern.matches(username).not()) errors += "User name contains invalid characters"
    if (content.key(keyId) == null) errors += "Choose a key, or create one under Keys first"
    if (jumpHostId != null && content.host(jumpHostId) == null) errors += "Unknown jump host"
    if (tags.any { tagPattern.matches(it).not() }) errors += "Tags may only contain letters, digits, dots, dashes and underscores"
    if (sourceAddressForTargets != null && SOURCE_ADDRESS_PATTERN.matches(sourceAddressForTargets).not())
        errors += "The address seen by hosts behind it may only contain addresses, host names, CIDR ranges and wildcards"
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
    )

    val candidate = content.copy(hosts = content.hosts.filterNot { it.id == host.id } + host)
    return when (val route = resolveRoute(candidate, host.id)) {
        is ResultOf2.Success -> ResultOf2.Success(host)
        is ResultOf2.Failure -> ResultOf2.Failure(listOf(route.value))
    }
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

private fun FlowContent.hostCard(dirl: Dirl, content: VaultContent, host: Host) = div("card host-card") {
    val state = dirl.connections.state(host.id)
    val sample = dirl.metrics.latest(host.id)
    div("title") {
        a(href = "/hosts/${host.id}") { +host.name }
        statePill(state)
    }
    div("addr") {
        +"${host.username}@${host.address}:${host.port}"
        host.jumpHostId?.let { content.host(it) }?.let { +" via ${it.name}" }
    }
    if (host.tags.isNotEmpty() || host.jumpOnly) div("chips") {
        if (host.jumpOnly) span("chip") { +"jump host" }
        host.tags.forEach { span("chip") { +"#$it" } }
    }
    if (sample != null && host.jumpOnly.not()) div("meters") {
        meter("CPU", sample.cpuPercent)
        meter("RAM", percentOf(sample.memUsedKiB, sample.memTotalKiB))
        val disk = sample.disks.filter { it.totalKiB > 0 }.maxByOrNull { it.usedKiB.toDouble() / it.totalKiB }
        meter("Disk", disk?.let { percentOf(it.usedKiB, it.totalKiB) })
    }
    div("btn-row") {
        if (host.jumpOnly.not()) {
            linkButton("/hosts/${host.id}/terminal", "Terminal", "primary sm")
            linkButton("/hosts/${host.id}/files", "Files", "sm")
        }
        linkButton("/hosts/${host.id}", "Details", "ghost sm")
    }
}

private fun FlowContent.meter(label: String, percent: Double?) = div("meter") {
    span { +label }
    val level = when {
        percent == null -> ""
        percent >= 90 -> " critical"
        percent >= 75 -> " high"
        else -> ""
    }
    div("bar$level") { span { style = "--v:${(percent ?: 0.0).roundToInt()}%" } }
    span("val") { +(percent?.let { "${it.roundToInt()}%" } ?: "...") }
}

private fun FlowContent.statePill(state: ConnectionState) = pill(
    when (state) {
        is ConnectionState.Connected -> "ok"
        ConnectionState.Idle, ConnectionState.Connecting -> ""
        is ConnectionState.Failed, is ConnectionState.AuthFailed, is ConnectionState.HostKeyUnknown -> "warn"
        is ConnectionState.Stopped, is ConnectionState.HostKeyMismatch -> "error"
    },
    when (state) {
        is ConnectionState.Connected -> "online"
        ConnectionState.Idle -> "idle"
        ConnectionState.Connecting -> "connecting"
        is ConnectionState.Failed -> "unreachable"
        is ConnectionState.AuthFailed -> "login rejected"
        is ConnectionState.Stopped -> "stopped"
        is ConnectionState.HostKeyUnknown -> "confirm host key"
        is ConnectionState.HostKeyMismatch -> "host key changed"
    },
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
    keyValues(
        "CPU" to (sample.cpuPercent?.let { "${it.roundToInt()}%" } ?: "unknown"),
        "Load (1 min)" to "%.2f".format(sample.load1),
        "RAM" to "${pct(sample.memUsedKiB, sample.memTotalKiB)} of ${gib(sample.memTotalKiB)}",
        "Swap" to if (sample.swapTotalKiB == 0L) "none" else "${pct(sample.swapUsedKiB, sample.swapTotalKiB)} of ${gib(sample.swapTotalKiB)}",
        "Uptime" to uptime(sample.uptimeSeconds),
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

private fun FlowContent.meterBar(percent: Double?) {
    val level = when {
        percent == null -> ""
        percent >= 90 -> " critical"
        percent >= 75 -> " high"
        else -> ""
    }
    div("bar$level") { span { style = "--v:${(percent ?: 0.0).roundToInt()}%" } }
    span("val") { +(percent?.let { "${it.roundToInt()}%" } ?: "") }
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
                    "Jump host only: no terminal, no files, no metrics. Its authorized_keys line then allows nothing but forwarding to the hosts behind it",
                    "jumpOnly", (form?.get("jumpOnly") ?: if (host?.jumpOnly == true) "on" else "") == "on",
                )
                textField(
                    "Address seen by hosts behind it", "sourceAddressForTargets", value("sourceAddressForTargets", host?.sourceAddressForTargets.orEmpty()),
                    hint = "Only for jump hosts. The address the hosts behind this one see it connecting from, often its address in their network. Fills from=\"...\" in their authorized_keys lines.",
                    required = false, placeholder = "e.g. 10.0.0.1",
                )
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

private fun uptime(seconds: Double): String {
    val days = (seconds / 86400).toInt()
    val hours = ((seconds % 86400) / 3600).toInt()
    return if (days > 0) "$days d $hours h" else "$hours h ${((seconds % 3600) / 60).toInt()} min"
}
