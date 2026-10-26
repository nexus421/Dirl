# Using Dirl

## What the UI covers

| Page      | What you can do                                                                                                          |
|-----------|--------------------------------------------------------------------------------------------------------------------------|
| Hosts     | Overview cards with state and the values chosen per host (CPU, RAM and fullest disk by default, also swap, every disk, load with cores, uptime, reboot needed, failed services, zram, system and kernel, logged in users), filter by tag. Add, edit, delete, connect now. A host can be marked "jump host only", a jump host takes the address the hosts behind it see it coming from |
| Host      | Connection details, host key confirmation and pin removal, the restricted `authorized_keys` line with copy button, every value of the latest poll, disks |
| Terminal  | xterm.js with resize, snippet buttons, a key bar with Ctrl, Esc, Tab, arrows on touch devices, Enter reloads after a disconnect. While connected, the browser asks before leaving the page (also on Ctrl+W), because leaving ends the shell. Run long jobs in `tmux` or `screen` |
| Files     | Breadcrumbs, path input, download, upload with progress (existing files only with "Overwrite existing files"), new directory, rename or move, delete. There is no editor, files are changed in the terminal. Symlinks are marked with →, they open, download and get overwritten like their target, deleting one removes only the link |
| Keys      | Generate Ed25519 or import on top, below one folded row per key with fingerprint and use (a new key opens right after it was added). Rename, export after entering the passphrase again, delete unused keys |
| Snippets  | Add, edit, delete, "run immediately" or "insert only", optional folder: each folder is a menu above the terminal |
| Audit     | The latest entries, filterable                                                                                           |
| Settings  | Access requests, allowed users, active sessions (end any), Dirl's source address, update check (on or off, latest release, a newer one shows in the footer of every page), passphrase change, encrypted backup download, seal now |
| Setup     | Create the vault, or restore an encrypted backup                                                                         |

[Back to the README](../README.md)
