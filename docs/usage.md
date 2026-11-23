# Using Dirl

## Pages

- **Hosts**: one row per host with a status color, the values you chose per host and the SSH round trip. Green is
  fine, yellow a warning (a value at 90 % or more, a round trip of 100 ms or more, a host key to confirm), red no
  connection. The page updates itself. Pin hosts, change the order under "Arrange", filter by tag.
- **Host**: connection, host key, the `authorized_keys` line for this host and a command that puts it in place,
  the latest values and disks.
- **Terminal**: snippet buttons (`⏎` runs on the click, `{ }` asks for values, unmarked ones show the command first),
  a key bar above the terminal on touch devices, [Actions mode](#actions-mode) for phones. A long press selects text on
  touch devices, [copy and paste](#copy-and-paste) with the mouse can be turned on. Leaving the page ends the shell,
  run long jobs in [tmux](#long-jobs-with-tmux).
- **Files**: browse, download, upload by dropping or choosing files (existing ones only with "Overwrite existing
  files"), new directory, rename, delete. There is no editor. A symlink behaves like its target, deleting one removes
  only the link.
- **Keys**: generate or import Ed25519 keys, rename, export (asks for the passphrase), delete unused ones.
- **Snippets**: commands as buttons above every terminal, in folders, with [placeholders](#placeholders-in-snippets),
  [export and import](#sharing-snippets).
- **Audit**: the latest entries, filterable.
- **Settings**: allowed users and access requests, sessions, Dirl's source address, update check, terminal clipboard,
  passphrase change, encrypted backup, seal.

"Reboot needed" compares the installed with the running kernel. On Arch and Alpine the kernel image has no version in
its name, there a host always shows it.

The round trip is an SSH request over the existing connection (no ICMP), through jump hosts the whole way from Dirl.
Each poll measures three times and shows the smallest, the first answer after a login is often slow.

## Actions mode

For a phone in an emergency: the terminal only shows output, input comes from the buttons Enter and Cancel (Ctrl+C)
and from the snippets in a panel. A tap on the terminal never opens the keyboard or clicks into a program. The button
in the terminal bar switches to the classic terminal, for a `sudo` password for example. Touch devices start in Actions,
the choice is remembered per device.

## Copy and paste

On a phone or tablet a long press selects text in the terminal, with the handles and the menu of the system, in both
modes. New output in the terminal drops the selection. With the keyboard open the first long press only closes it.
A program with mouse support in the classic terminal (mc, htop) still gets taps as clicks.

With a mouse, "Copy selected text and paste with a right click" under Settings, off by default, works like PuTTY:

- Selecting text copies it.
- A right click pastes. Ctrl+C stays the interrupt of the shell, Ctrl+Shift+V still pastes too.
- Text with a line break that the shell would run right away (no bracketed paste) first shows up above the terminal
  with Send and Cancel, from a right click as from Ctrl+Shift+V. Shells with bracketed paste (bash 5.1 and later, zsh, fish) only put it on the command line.
  Text with other control characters always asks, they show as `^[`, `^C` and so on: an escape could end the
  bracketed paste early and run the rest.
- A program with mouse support (htop, vim, tmux with `mouse on`) gets the right click itself.
- The browser only allows the clipboard over HTTPS. Chrome asks once, Firefox on every paste.

With the setting off nothing asks, Ctrl+Shift+V pastes as it did before 1.2.0.

The setting applies to every user. While it is on, Dirl versions before 1.2.0 cannot open the vault, turn it off before
going back to such a version. The same holds for a backup made while it was on: only 1.2.0 and later restore it.

## Long jobs with tmux

The shell ends with the connection, and with it a running `apt upgrade`. "Add tmux snippets" on the Snippets page adds
two snippets:

- **Start tmux** `tmux new -A -s {{Session:dirl}}` starts the session or attaches to it.
- **Stop tmux** `tmux kill-session -t {{Session:dirl}}` ends it and the job in it.

Start tmux, run the job, and after a disconnect start tmux again: the job is still there. Scroll back with Ctrl+B, `[`
in the classic terminal. All Dirl users log in with the same account, so the session `dirl` is shared, see
[Security](security.md#ssh). Pick another name for a session of your own. tmux must be installed on the host.

## Placeholders in snippets

`{{Name}}` or `{{Name:default}}` in a command asks for a value before sending, for example
`docker logs --tail {{Lines:100}} -f {{Container}}`. A form above the terminal shows a field per name and a preview,
Enter sends, Escape cancels. Names hold letters, digits, `_` and `-`, at most 10 per snippet. Templates with a dot or
a space such as Docker's `{{.Names}}` stay as they are. A value is typed as given without quoting, so write
`cat "{{File}}"` where it may hold spaces. Line breaks and control characters are removed from values.

## Sharing snippets

"Export all" downloads `dirl-snippets-<date>.json`:

```json
{
  "dirlSnippets": 1,
  "snippets": [
    { "name": "Disk usage", "command": "df -h", "folder": "System", "run": true },
    { "name": "Tail syslog", "command": "journalctl -f", "run": false }
  ]
}
```

`folder` and `run` are optional, `run` decides whether the command runs at once or asks first. A plain list without
the outer object works too, handy for files an AI tool writes. The import shows a preview first: new, replacing
(old and new command side by side) or unchanged, one checkbox per row, optionally "Delete all other snippets". A file
with a problem (rules of the snippet form, duplicates, unknown fields, hidden characters such as U+202E) is refused
with every problem listed. At most 500 snippets and 1 MiB.

## Install as an app

Chrome: "Install app" or "Add to Home screen", Safari on iOS: Share, "Add to Home Screen". Dirl then opens in its own
window. Nothing is cached, and on iOS the app needs its own login.

[Back to the README](../README.md)
