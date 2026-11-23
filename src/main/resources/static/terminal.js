// Terminal page: connects xterm.js to /ws/terminal/{id}.
// Binary frames carry terminal bytes in both directions, text frames are JSON control messages.
// Loaded as a file because the CSP forbids inline scripts. Server output only ever goes into xterm, never into the DOM.
'use strict';
(function () {
  const el = document.getElementById('terminal');
  if (!el) return;

  const term = new Terminal({
    cursorBlink: true,
    scrollback: 5000,
    fontFamily: 'ui-monospace, "JetBrains Mono", "DejaVu Sans Mono", Menlo, Consolas, monospace',
    fontSize: 14,
    // With the default line height of 1 the DOM renderer clips glyphs below the cell, so underscores vanish in fonts
    // like DejaVu Sans Mono at 14px.
    lineHeight: 1.1,
    theme: { background: '#0b0d10' },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(el);
  fit.fit();

  const encoder = new TextEncoder();
  let ws = null;
  let closed = true;

  function connect() {
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(scheme + '//' + location.host + el.dataset.ws + '?cols=' + term.cols + '&rows=' + term.rows);
    ws.binaryType = 'arraybuffer';
    closed = false;
    ws.onmessage = function (event) {
      if (typeof event.data !== 'string') {
        term.write(new Uint8Array(event.data));
        return;
      }
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'error') term.write('\r\n\x1b[31m' + message.message + '\x1b[0m\r\n');
      } catch (ignored) {
        // Unknown control messages are ignored.
      }
    };
    ws.onclose = function () {
      closed = true;
      term.write('\r\n\x1b[33m[connection closed, press Enter to reload]\x1b[0m\r\n');
    };
  }

  // Leaving the page closes the shell on the server, and Ctrl+W, which deletes a word in the shell, closes the tab in
  // the browser. While the connection is open the browser asks first. After a disconnect it does not, so Enter can
  // reload.
  window.addEventListener('beforeunload', function (event) {
    if (closed) return;
    event.preventDefault();
    event.returnValue = '';
  });

  // Sticky Ctrl from the key bar: the next single character is sent as control character.
  const ctrlButton = document.getElementById('ctrl');
  let ctrl = false;
  function setCtrl(active) {
    ctrl = active;
    if (ctrlButton) ctrlButton.classList.toggle('active', active);
  }

  // Two modes. Terminal is the classic one with the keyboard. Actions is for touch screens: the terminal only shows
  // output, input comes from the snippets and from Enter and Cancel below it, so the on-screen keyboard stays closed.
  // The mode is remembered per device. Without a stored one a touch screen starts in Actions, judged by the pointer and
  // never by the user agent.
  const page = el.closest('.term-page');
  const modeButton = document.getElementById('mode');
  const modeKey = 'dirl.terminalMode';
  function storedMode() {
    try {
      return localStorage.getItem(modeKey);
    } catch (ignored) {
      return null;
    }
  }
  const stored = storedMode();
  let actionsMode = stored === 'actions' || (stored !== 'terminal' && window.matchMedia('(pointer: coarse)').matches);
  function focusTerminal() {
    if (actionsMode === false) term.focus();
  }
  function applyMode() {
    page.classList.toggle('actions', actionsMode);
    // Not disableStdin: it would also drop the answers of xterm to queries of the host (cursor position, device
    // attributes, colours), which shells and tmux wait for. A read-only textarea with inputmode="none" keeps the
    // keyboard closed when the terminal is tapped to scroll, the handlers below hold back keys, paste and the mouse.
    term.textarea.readOnly = actionsMode;
    if (actionsMode) term.textarea.setAttribute('inputmode', 'none');
    else term.textarea.removeAttribute('inputmode');
    if (modeButton) modeButton.textContent = actionsMode ? 'Classic terminal' : 'Actions';
    setCtrl(false);
    fit.fit();
    placeAsk();
    // An open snippet form keeps the focus.
    if (actionsMode) term.blur();
    else if (asking === null) term.focus();
  }
  // In Actions mode only what the user enters is held back: keys, pasted or dropped text and mouse reports, X10
  // (ESC [ M) and SGR (ESC [ <). Everything else xterm sends is an answer to the host and goes out.
  const mouseReport = /^\x1b\[[M<]/;
  term.attachCustomKeyEventHandler(function () { return actionsMode === false; });
  ['paste', 'drop'].forEach(function (type) {
    el.addEventListener(type, function (event) {
      if (actionsMode === false) return;
      event.preventDefault();
      event.stopPropagation();
    }, true);
  });

  function send(text) {
    if (closed) {
      // Enter reloads the page instead of opening only a new terminal socket. That also reopens the presence socket
      // (app.js) after a sleep or a restart, and leads to the login when the session ended. The shell is new anyway.
      if (text === '\r') location.reload();
      return;
    }
    if (ws.readyState !== WebSocket.OPEN) return;
    if (ctrl && text.length === 1) {
      const code = text.toUpperCase().charCodeAt(0);
      if (code >= 64 && code <= 95) text = String.fromCharCode(code - 64);
      setCtrl(false);
    }
    ws.send(encoder.encode(text));
  }

  term.onData(function (data) {
    if (actionsMode && mouseReport.test(data)) return;
    send(data);
  });
  // Some mouse reports are not valid UTF-8 and arrive here as raw bytes.
  term.onBinary(function (data) {
    if (actionsMode) return;
    if (!closed && ws.readyState === WebSocket.OPEN) ws.send(Uint8Array.from(data, function (c) { return c.charCodeAt(0); }));
  });
  term.onResize(function (size) {
    if (!closed && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows }));
  });
  window.addEventListener('resize', function () {
    fit.fit();
    placeAsk();
  });

  // Snippet folders are <details class="menu">: close them after a snippet was sent, on a click elsewhere and on
  // Escape. Opening one closes the others. Without JavaScript they still open and close by clicking the folder.
  const menus = document.querySelectorAll('details.menu');
  function closeMenus(except) {
    menus.forEach(function (menu) { if (menu !== except) menu.open = false; });
  }
  document.addEventListener('click', function (event) {
    closeMenus(event.target.closest('details.menu'));
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') closeMenus(null);
  });

  // Placeholders: {{Name}} or {{Name:default}}, the same pattern as PLACEHOLDER_PATTERN in SnippetPlaceholders.kt.
  // The u flag makes {0,200} count characters like Kotlin does, without it an emoji would count twice.
  // A snippet with placeholders first asks for their values above the terminal, then sends the filled command. A
  // snippet that does not run immediately shows its command there with Send and Cancel, Send runs it.
  const placeholderPattern = /\{\{([A-Za-z0-9_-]{1,32})(?::((?:(?!\}\})[^\r\n]){0,200}))?\}\}/gu;
  function placeholdersOf(command) {
    const byName = new Map();
    command.replace(placeholderPattern, function (all, name, value) {
      if (!byName.has(name) || (byName.get(name) === undefined && value !== undefined)) byName.set(name, value);
      return all;
    });
    return byName;
  }
  // A value is typed into the shell as it is. Line breaks and other control characters are dropped, so a value
  // can never run the command early or send keys of its own.
  function cleanValue(value) {
    return value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 500);
  }
  function fillPlaceholders(command, values) {
    return command.replace(placeholderPattern, function (all, name) { return values[name]; });
  }
  // Pasted text reaches the shell as it is. A line break in it runs the command right away, unless the shell takes
  // pastes bracketed and only puts them on the command line. Without brackets Dirl asks first. Other control
  // characters always ask: xterm passes an escape on, and \e[201~ in the text would end the bracket early.
  function pasteNeedsConfirm(text, bracketed) {
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text) || (bracketed !== true && /[\r\n]/.test(text));
  }
  // The paste preview shows line breaks as lines and every other control character in caret notation (^[ for an
  // escape), so nothing that would be sent stays invisible.
  function showControls(text) {
    return text.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, function (c) {
      return c === '\u007f' ? '^?' : '^' + String.fromCharCode(c.charCodeAt(0) + 64);
    });
  }
  // Where the "Copied" hint goes, in pixels from the top left of the terminal: centred a little above the point where
  // the mouse let go, below it when there is no room above, and inside the terminal as far as it fits. A point outside
  // the terminal (the drag ended elsewhere) counts as the nearest edge.
  function hintPosition(x, y, width, height, boxWidth, boxHeight) {
    const margin = 4;
    const gap = 6;
    const pointerHeight = 20;
    const px = Math.min(Math.max(Number.isFinite(x) ? x : 0, 0), boxWidth);
    const py = Math.min(Math.max(Number.isFinite(y) ? y : 0, 0), boxHeight);
    let top = py - height - gap;
    if (top < margin) top = py + pointerHeight;
    top = Math.max(Math.min(top, boxHeight - height - margin), 0);
    const left = Math.max(Math.min(Math.max(px - width / 2, margin), boxWidth - width - margin), 0);
    return { left: Math.round(left), top: Math.round(top) };
  }

  // Password managers ignore autocomplete="off" and offer to fill a field labelled "Name" with a person's name.
  // These are the attributes the common ones honour instead: Proton Pass, 1Password, Bitwarden, LastPass, Dashlane.
  function noPasswordManager(element) {
    element.setAttribute('data-protonpass-ignore', 'true');
    element.setAttribute('data-1p-ignore', 'true');
    element.setAttribute('data-bwignore', 'true');
    element.setAttribute('data-lpignore', 'true');
    element.setAttribute('data-form-type', 'other');
  }

  const ask = document.createElement('form');
  ask.className = 'snippet-ask';
  ask.hidden = true;
  ask.autocomplete = 'off';
  ask.setAttribute('aria-label', 'Send the snippet');
  noPasswordManager(ask);
  const askTitle = document.createElement('div');
  askTitle.className = 'snippet-ask-title';
  const askFields = document.createElement('div');
  askFields.className = 'snippet-ask-fields';
  const askPreview = document.createElement('pre');
  askPreview.className = 'snippet-ask-preview';
  const askButtons = document.createElement('div');
  askButtons.className = 'btn-row';
  const askSend = document.createElement('button');
  askSend.type = 'submit';
  askSend.className = 'btn primary sm';
  askSend.textContent = 'Send';
  const askCancel = document.createElement('button');
  askCancel.type = 'button';
  askCancel.className = 'btn ghost sm';
  askCancel.textContent = 'Cancel';
  askButtons.append(askSend, askCancel);
  ask.append(askTitle, askFields, askPreview, askButtons);
  el.parentNode.insertBefore(ask, el);
  let asking = null;

  function askValues() {
    // No prototype, so a placeholder named __proto__ or constructor is an ordinary key.
    const values = Object.create(null);
    askFields.querySelectorAll('input').forEach(function (input) { values[input.name] = cleanValue(input.value); });
    return values;
  }
  // The preview is the command with every value marked, so a rarely used command shows what goes where. The value of
  // the field with the focus is marked stronger, an empty one shows its name. Built from text nodes, never markup.
  function updatePreview() {
    const values = askValues();
    const focused = document.activeElement && document.activeElement.form === ask ? document.activeElement.name : null;
    const command = asking.command.replace(/\n$/, '');
    const parts = [];
    let last = 0;
    command.replace(placeholderPattern, function (all, name, value, offset) {
      if (offset > last) parts.push(document.createTextNode(command.slice(last, offset)));
      const mark = document.createElement('span');
      mark.className = 'var' + (name === focused ? ' active' : '') + (values[name] === '' ? ' missing' : '');
      mark.textContent = values[name] === '' ? '<' + name + '>' : values[name];
      parts.push(mark);
      last = offset + all.length;
      return all;
    });
    if (last < command.length) parts.push(document.createTextNode(command.slice(last)));
    askPreview.replaceChildren.apply(askPreview, parts);
  }
  // Enter of the action bar, disabled while the snippet form is open.
  const actionEnter = document.querySelector('.actionbar [data-key="enter"]');
  function closeAsk() {
    ask.hidden = true;
    asking = null;
    if (actionEnter) actionEnter.disabled = false;
    askFields.replaceChildren();
    focusTerminal();
  }
  // Right at the top left of the terminal, wherever the bar above it ends (it wraps on a phone) and wherever the
  // snippet panel of the Actions mode puts it.
  function placeAsk() {
    ask.style.top = (el.offsetTop + 8) + 'px';
    ask.style.left = (el.offsetLeft + 8) + 'px';
  }
  function openAsk(button, placeholders) {
    asking = { command: button.dataset.send };
    askTitle.textContent = button.dataset.name || button.textContent;
    askFields.replaceChildren();
    placeholders.forEach(function (value, name) {
      const label = document.createElement('label');
      label.className = 'field';
      const caption = document.createElement('span');
      caption.textContent = name;
      const input = document.createElement('input');
      input.type = 'text';
      input.name = name;
      input.value = value === undefined ? '' : value;
      input.required = true;
      input.autocomplete = 'off';
      input.spellcheck = false;
      noPasswordManager(input);
      input.addEventListener('input', updatePreview);
      input.addEventListener('focus', updatePreview);
      label.append(caption, input);
      askFields.append(label);
    });
    placeAsk();
    ask.hidden = false;
    if (actionEnter) actionEnter.disabled = true;
    updatePreview();
    // Enter sends: in a field it submits the form, without fields Send has the focus.
    const first = askFields.querySelector('input');
    if (first) {
      first.focus();
      first.select();
    } else askSend.focus();
  }
  // The same form asks before a paste with a line break, the text as preview and no fields.
  function openPaste(text) {
    asking = { paste: text };
    askTitle.textContent = 'Paste';
    askFields.replaceChildren();
    askPreview.replaceChildren(document.createTextNode(showControls(text)));
    placeAsk();
    ask.hidden = false;
    if (actionEnter) actionEnter.disabled = true;
    askSend.focus();
  }
  ask.addEventListener('submit', function (event) {
    event.preventDefault();
    if (!asking) return;
    if (asking.paste !== undefined) {
      // Pasted as it is: no placeholders, no line break added. xterm brackets it when the shell asked for that.
      const text = asking.paste;
      closeAsk();
      term.paste(text);
      return;
    }
    // Send always runs the command, also one stored without the Enter of "run immediately".
    const command = fillPlaceholders(asking.command, askValues()).replace(/\n?$/, '\n');
    closeAsk();
    send(command);
  });
  askCancel.addEventListener('click', closeAsk);
  ask.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      event.stopPropagation();
      closeAsk();
    }
  });

  // Whether the pointer that last went down on the terminal was a finger. Mouse input never depends on it.
  let touch = false;
  el.addEventListener('pointerdown', function (event) { touch = event.pointerType === 'touch'; }, true);
  // A long press selects text natively, where app.css turns that on (pointer: coarse, the same query as here). xterm
  // must not see the touch: on the contextmenu of the long press it moves its input field under the finger and
  // Android selects that empty field instead, and after a tap it redraws the rows on the next long press, which drops
  // the selection. Without the tap xterm does not focus itself, so the classic terminal does that here to bring up the
  // keyboard. A program with mouse support in the classic terminal still gets the taps, as before.
  const nativeSelection = window.matchMedia('(pointer: coarse)');
  ['mousedown', 'mouseup', 'click', 'dblclick', 'contextmenu'].forEach(function (type) {
    el.addEventListener(type, function (event) {
      if (touch === false || nativeSelection.matches === false) return;
      if (actionsMode === false && term.modes.mouseTrackingMode !== 'none') return;
      event.stopPropagation();
      if (type === 'click') focusTerminal();
    }, true);
  });

  // Copy on select and paste on right click, only when turned on in the settings (data-clipboard on the terminal) and
  // only with a mouse. Ctrl+C stays the interrupt of the shell. Reading the clipboard needs HTTPS or localhost, Chrome
  // asks once, Firefox on every paste. A refused or failed read does nothing.
  function pasteText(text) {
    if (typeof text !== 'string' || text === '' || asking !== null) return;
    if (pasteNeedsConfirm(text, term.modes.bracketedPasteMode)) openPaste(text);
    else term.paste(text);
  }
  if (el.dataset.clipboard === 'on') {
    // A selection starts on the terminal but may end anywhere on the page, so the release is watched on the document.
    // The press is watched in the capture phase, only read and never stopped: xterm stops it when Shift forces a
    // selection in a program with mouse support (htop, vim, tmux). There only Shift selects, a plain click belongs to
    // the program and must not copy a selection that is still shown.
    let selecting = false;
    // "Copied" near the mouse once the clipboard took the text, gone after a moment. Only this fixed word goes into
    // the page, never the copied text. It lets every click through and does not move (no animation).
    const copyHint = document.createElement('div');
    copyHint.className = 'copy-hint';
    copyHint.hidden = true;
    copyHint.setAttribute('role', 'status');
    el.parentNode.insertBefore(copyHint, el);
    let copyHintTimer = null;
    function hideCopied() {
      clearTimeout(copyHintTimer);
      copyHint.hidden = true;
      copyHint.textContent = '';
    }
    function showCopied(x, y) {
      copyHint.textContent = 'Copied';
      copyHint.hidden = false;
      const at = hintPosition(x, y, copyHint.offsetWidth, copyHint.offsetHeight, el.offsetWidth, el.offsetHeight);
      copyHint.style.left = (el.offsetLeft + at.left) + 'px';
      copyHint.style.top = (el.offsetTop + at.top) + 'px';
      clearTimeout(copyHintTimer);
      copyHintTimer = setTimeout(hideCopied, 1500);
    }
    // A press elsewhere ends a selection whose release the page never saw (let go outside the window), so a later
    // click on a button does not copy again.
    document.addEventListener('mousedown', function (event) {
      if (el.contains(event.target) === false) selecting = false;
    }, true);
    el.addEventListener('mousedown', function (event) {
      hideCopied();
      selecting = touch === false && event.button === 0 && (term.modes.mouseTrackingMode === 'none' || event.shiftKey);
    }, true);
    document.addEventListener('mouseup', function (event) {
      if (selecting === false || event.button !== 0) return;
      selecting = false;
      if (!navigator.clipboard) return;
      const box = el.getBoundingClientRect();
      const x = event.clientX - box.left;
      const y = event.clientY - box.top;
      // After xterm has finished the selection, still within the click that allows writing the clipboard.
      setTimeout(function () {
        // Only empty cells selected (past the end of a line) gives no text: the clipboard keeps what it holds.
        const text = term.hasSelection() ? term.getSelection() : '';
        if (text === '') return;
        navigator.clipboard.writeText(text).then(function () { showCopied(x, y); }, function () {});
      }, 0);
    });
    el.addEventListener('contextmenu', function (event) {
      if (touch || actionsMode || asking !== null || !navigator.clipboard || !navigator.clipboard.readText) return;
      // A program with mouse support (htop, vim, tmux) gets the right click itself, as in other terminals.
      if (term.modes.mouseTrackingMode !== 'none') return;
      event.preventDefault();
      event.stopPropagation();
      navigator.clipboard.readText().then(pasteText, function () {});
      focusTerminal();
    }, true);
    // The browser's own paste (Ctrl+Shift+V, the menu) gets the same question before a line break runs it.
    el.addEventListener('paste', function (event) {
      if (actionsMode || !event.clipboardData) return;
      const text = event.clipboardData.getData('text/plain');
      if (pasteNeedsConfirm(text, term.modes.bracketedPasteMode) === false) return;
      event.preventDefault();
      event.stopPropagation();
      pasteText(text);
    }, true);
  }

  document.querySelectorAll('[data-send]').forEach(function (button) {
    button.addEventListener('click', function () {
      closeMenus(null);
      // The keys of the key bar are sent as they are.
      const placeholders = placeholdersOf(button.dataset.send);
      const asks = placeholders.size > 0 || button.dataset.send.endsWith('\n') === false;
      if (asks && button.closest('.keybar') === null) {
        openAsk(button, placeholders);
        return;
      }
      send(button.dataset.send);
      focusTerminal();
    });
  });
  // The action bar of the Actions mode sends Enter and Ctrl+C. While the snippet form is open the bar belongs to it:
  // Cancel closes the form and Enter is disabled, so neither reaches a running job by a slip of the thumb.
  const actionKeys = { enter: '\r', cancel: '\u0003' };
  document.querySelectorAll('.actionbar [data-key]').forEach(function (button) {
    button.addEventListener('click', function () {
      if (asking) {
        if (button.dataset.key === 'cancel') closeAsk();
        return;
      }
      send(actionKeys[button.dataset.key]);
    });
  });
  if (ctrlButton) ctrlButton.addEventListener('click', function () {
    setCtrl(!ctrl);
    focusTerminal();
  });
  if (modeButton) modeButton.addEventListener('click', function () {
    actionsMode = actionsMode === false;
    try {
      localStorage.setItem(modeKey, actionsMode ? 'actions' : 'terminal');
    } catch (ignored) {
      // Without storage the mode still switches, it is just not remembered.
    }
    applyMode();
  });

  // Before connecting, so the shell starts with the size of the chosen layout.
  applyMode();
  connect();
})();
