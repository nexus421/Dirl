package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.VaultContent
import kotnexlib.ResultOf2

/** At most this many jump hosts between Dirl and a target. */
const val MAX_JUMP_HOSTS = 2

/**
 * Resolves the chain of hosts needed to reach [hostId], first hop first and the target last.
 *
 * Rejects unknown hosts, unknown keys, cycles (A jumps via B, B via A) and chains longer than [MAX_JUMP_HOSTS] jump
 * hosts, so a broken configuration fails on save and not with a stack overflow at connect time.
 *
 * @return the route, or a reason to show to the user.
 */
fun resolveRoute(content: VaultContent, hostId: String): ResultOf2<List<Host>, String> {
    val route = ArrayDeque<Host>()
    var currentId: String? = hostId
    while (currentId != null) {
        val host = content.host(currentId) ?: return ResultOf2.Failure("Unknown host $currentId")
        if (route.any { it.id == host.id }) return ResultOf2.Failure("Jump host cycle at ${host.name}")
        if (content.key(host.keyId) == null) return ResultOf2.Failure("Host ${host.name} references a deleted key")
        route.addFirst(host)
        if (route.size > MAX_JUMP_HOSTS + 1) return ResultOf2.Failure("More than $MAX_JUMP_HOSTS jump hosts for ${content.host(hostId)?.name}")
        currentId = host.jumpHostId
    }
    return ResultOf2.Success(route.toList())
}
