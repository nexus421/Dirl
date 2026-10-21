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

  document.querySelectorAll('[data-send]').forEach(function (button) {
    button.addEventListener('click', function () {
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
