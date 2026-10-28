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

  term.onData(send);
  // Some mouse reports are not valid UTF-8 and arrive here as raw bytes.
  term.onBinary(function (data) {
    if (!closed && ws.readyState === WebSocket.OPEN) ws.send(Uint8Array.from(data, function (c) { return c.charCodeAt(0); }));
  });
  term.onResize(function (size) {
    if (!closed && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows }));
  });
  window.addEventListener('resize', function () { fit.fit(); });

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
  // A snippet with placeholders first asks for their values above the terminal, then sends the filled command.
  const placeholderPattern = /\{\{([A-Z][A-Za-z0-9_-]{0,31})(?::([^{}\r\n]{0,200}))?\}\}/g;
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

  const ask = document.createElement('form');
  ask.className = 'snippet-ask';
  ask.hidden = true;
  ask.setAttribute('aria-label', 'Values for the snippet');
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
  const askCancel = document.createElement('button');
  askCancel.type = 'button';
  askCancel.className = 'btn ghost sm';
  askCancel.textContent = 'Cancel';
  askButtons.append(askSend, askCancel);
  ask.append(askTitle, askFields, askPreview, askButtons);
  el.parentNode.insertBefore(ask, el);
  let asking = null;

  function askValues() {
    const values = {};
    askFields.querySelectorAll('input').forEach(function (input) { values[input.name] = cleanValue(input.value); });
    return values;
  }
  function updatePreview() {
    askPreview.textContent = fillPlaceholders(asking.command, askValues()).replace(/\n$/, '');
  }
  function closeAsk() {
    ask.hidden = true;
    asking = null;
    askFields.replaceChildren();
    term.focus();
  }
  function openAsk(button, placeholders) {
    asking = { command: button.dataset.send };
    askTitle.textContent = button.textContent;
    askSend.textContent = button.dataset.send.endsWith('\n') ? 'Run' : 'Insert';
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
      input.addEventListener('input', updatePreview);
      label.append(caption, input);
      askFields.append(label);
    });
    // Right at the top of the terminal, wherever the bar above it ends (it wraps on a phone).
    ask.style.top = (el.offsetTop + 8) + 'px';
    ask.hidden = false;
    updatePreview();
    const first = askFields.querySelector('input');
    first.focus();
    first.select();
  }
  ask.addEventListener('submit', function (event) {
    event.preventDefault();
    if (!asking) return;
    const command = fillPlaceholders(asking.command, askValues());
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

  document.querySelectorAll('[data-send]').forEach(function (button) {
    button.addEventListener('click', function () {
      closeMenus(null);
      const placeholders = placeholdersOf(button.dataset.send);
      if (placeholders.size > 0 && button.closest('.keybar') === null) {
        openAsk(button, placeholders);
        return;
      }
      send(button.dataset.send);
      term.focus();
    });
  });
  if (ctrlButton) ctrlButton.addEventListener('click', function () {
    setCtrl(!ctrl);
    term.focus();
  });

  connect();
  term.focus();
})();
