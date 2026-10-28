# Using Dirl

## What the UI covers

| Page      | What you can do                                                                                                          |
|-----------|--------------------------------------------------------------------------------------------------------------------------|
| Hosts     | One row per host: a status bar in green, yellow (a warning, a value at 90 % or more, a round trip of 100 ms or more, a host key to confirm) or red (no connection), warnings and tags below the name, the values chosen per host (CPU, RAM and fullest disk by default, also swap, every disk, load with cores, uptime, reboot needed, failed services, zram, system and kernel, logged in users), the SSH round trip and Terminal and Files. A click on the row opens the host. Pin hosts to the top, change the order under "Arrange", filter by tag. Add, edit, delete, connect now. A host can be marked "jump host only", a jump host takes the address the hosts behind it see it coming from |
| Host      | Connection details, host key confirmation and pin removal, the restricted `authorized_keys` line with copy button, every value of the latest poll, disks |
| Terminal  | xterm.js with resize, snippet buttons, a key bar with Ctrl, Esc, Tab, arrows on touch devices, Enter reloads after a disconnect. While connected, the browser asks before leaving the page (also on Ctrl+W), because leaving ends the shell. Run long jobs in `tmux` or `screen` |
| Files     | Breadcrumbs, path input, download, upload with progress (existing files only with "Overwrite existing files"), new directory, rename or move, delete. There is no editor, files are changed in the terminal. Symlinks are marked with →, they open, download and get overwritten like their target, deleting one removes only the link |
| Keys      | Generate Ed25519 or import on top, below one folded row per key with fingerprint and use (a new key opens right after it was added). Rename, export after entering the passphrase again, delete unused keys |
| Snippets  | Add, edit, delete, "run immediately" or "insert only", optional folder: each folder is a menu above the terminal and a folded group on this page, the one just changed opens. Export all as JSON, import a dropped, chosen or pasted file with a preview, see below |
| Audit     | The latest entries, filterable                                                                                           |
| Settings  | Access requests, allowed users, active sessions (end any), Dirl's source address (several separated by commas, or no restriction at all), update check (on or off, latest release, a newer one shows in the footer of every page), passphrase change, encrypted backup download, seal now |
| Login     | A terminal that types `dirl scan` and lists what Dirl does, next to the sign in through the identity provider. The motion runs once and stops with the system setting for reduced motion |
| Setup     | Create the vault, or restore an encrypted backup                                                                         |

## Sharing snippets

"Export all" on the Snippets page downloads every snippet as `dirl-snippets-<date>.json`:

```json
{
  "dirlSnippets": 1,
  "snippets": [
    { "name": "Disk usage", "command": "df -h", "folder": "System", "run": true },
    { "name": "Tail syslog", "command": "journalctl -f", "run": false }
  ]
}
```

`folder` and `run` are optional, `run` decides whether Enter is sent after the command. A plain list of snippets
without the outer object is read as well, which makes it easy to have an AI tool write one. There are no IDs, the file
works on any Dirl.

The import takes a file or pasted JSON and first shows a preview, nothing is saved before "Import selected". A snippet
counts as existing when folder and name match, ignoring case. The preview marks every snippet as new, as replacing an
existing one (with the old and the new command next to each other) or as already there and unchanged, and highlights
the ones that run immediately. Every row has a checkbox:

- "Replace the existing one" or "Keep the existing one" ticks or unticks every row that would replace a snippet.
- Unticking a row leaves it out.
- "Delete all other snippets and keep only the ones selected here" removes every snippet that is not in the file and
  every existing one whose row is not ticked.

A file with a problem is refused as a whole, with every problem and the number of the snippet: the same rules as the
snippet form, two snippets with the same folder and name, unknown fields. At most 500 snippets and 1 MiB.

## Round trip

The overview shows how long an SSH request to each host and its answer take, measured on every status poll over the
existing connection (OpenSSH's `keepalive@openssh.com`). Through jump hosts it is the whole way from Dirl to the
host, from Dirl's point of view, not from the browser. Green below 100 ms, yellow from 100 ms on, `offline` in red
without a connection. No ICMP, so it needs no rights and works where ping is blocked.

[Back to the README](../README.md)
