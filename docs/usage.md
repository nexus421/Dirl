# Using Dirl

## What the UI covers

| Page      | What you can do                                                                                                          |
|-----------|--------------------------------------------------------------------------------------------------------------------------|
| Hosts     | Overview cards with state, CPU, RAM and fullest disk, filter by tag. Add, edit, delete, connect now, disconnect. A host can be marked "jump host only" |
| Host      | Connection details, host key confirmation and pin removal, the restricted `authorized_keys` line with copy button, metrics with 24 hour charts, disks |
| Terminal  | xterm.js with resize, snippet buttons, a key bar with Ctrl, Esc, Tab, arrows on touch devices, Enter reconnects          |
| Files     | Breadcrumbs, path input, download, upload with progress (existing files only with "Overwrite existing files"), new directory, rename or move, delete, UTF-8 editor up to 1 MiB. Symlinks are marked with →, they open and save like their target, deleting one removes only the link |
| Keys      | Generate Ed25519, import, rename, export after entering the passphrase again, delete unused keys, fingerprints           |
| Snippets  | Add, edit, delete, "run immediately" or "insert only"                                                                    |
| Audit     | The latest entries, filterable                                                                                           |
| Settings  | Access requests, allowed users, active sessions (end any), Dirl's source address, passphrase change, encrypted backup download, seal now |
| Setup     | Create the vault, or restore an encrypted backup                                                                         |

[Back to the README](../README.md)
