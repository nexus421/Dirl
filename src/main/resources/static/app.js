// Small progressive enhancements for every page. Everything works without it, just with fewer comforts.
// Loaded as a file because the CSP forbids inline scripts.
'use strict';
(function () {
  // Presence: while a Dirl page is open, Dirl keeps the SSH connections to the hosts, once no page is open it closes
  // them. Nothing is sent over this socket. It is not reopened when it closes: a page whose session ended would
  // otherwise retry forever. The next page load opens a new one, also when the browser shows a page from its
  // back/forward cache, where the old socket was closed.
  const presencePath = document.body.dataset.presence;
  function openPresence() {
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    // The reference and the listener keep the browser from collecting and closing the socket.
    const socket = new WebSocket(scheme + '//' + location.host + presencePath);
    socket.addEventListener('close', function () {
      if (window.dirlPresence === socket) window.dirlPresence = null;
    });
    window.dirlPresence = socket;
  }
  if (presencePath) {
    openPresence();
    window.addEventListener('pageshow', function (event) {
      if (event.persisted && !window.dirlPresence) openPresence();
    });
  }

  // Confirmation before destructive actions: <form data-confirm="Delete this host?">
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  // Arrange hosts: the arrows move a row and renumber every position, a typed number moves the row there. Saving
  // stays one form post. Without JavaScript the arrows stay hidden and the numbers are typed.
  const arrange = document.querySelector('form[data-arrange]');
  if (arrange) {
    const list = arrange.querySelector('.arrange-list');
    const state = arrange.querySelector('[data-arrange-state]');
    const rows = function () { return Array.prototype.slice.call(list.querySelectorAll('[data-arrange-row]')); };
    const renumber = function () {
      const all = rows();
      all.forEach(function (row, i) {
        row.querySelector('input').value = i + 1;
        row.querySelector('[data-move=up]').disabled = i === 0;
        row.querySelector('[data-move=down]').disabled = i === all.length - 1;
      });
    };
    const changed = function () {
      renumber();
      if (state) state.textContent = 'Unsaved changes';
    };
    list.querySelectorAll('[data-move]').forEach(function (button) {
      button.hidden = false;
      button.addEventListener('click', function () {
        const row = button.closest('[data-arrange-row]');
        if (button.dataset.move === 'up' && row.previousElementSibling) list.insertBefore(row, row.previousElementSibling);
        if (button.dataset.move === 'down' && row.nextElementSibling) list.insertBefore(row.nextElementSibling, row);
        changed();
        button.focus();
      });
    });
    list.querySelectorAll('[data-arrange-row] input').forEach(function (input) {
      input.addEventListener('change', function () {
        const row = input.closest('[data-arrange-row]');
        const others = rows().filter(function (r) { return r !== row; });
        const target = Math.min(Math.max(parseInt(input.value, 10) || 1, 1), others.length + 1);
        list.insertBefore(row, others[target - 1] || null);
        changed();
      });
    });
    renumber();
  }

  // Drop zone of the snippet import: a dropped file goes into the hidden file input, the chosen file is named.
  document.querySelectorAll('[data-drop]').forEach(function (zone) {
    const input = zone.querySelector('input[type=file]');
    const main = zone.querySelector('.drop-main');
    const sub = zone.querySelector('.drop-sub');
    const show = function () {
      const file = input.files && input.files[0];
      if (!file) return;
      zone.classList.add('has');
      main.textContent = file.name;
      sub.textContent = (file.size / 1024).toFixed(1) + ' KiB, click to choose another';
    };
    input.addEventListener('change', show);
    ['dragenter', 'dragover'].forEach(function (name) {
      zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.remove('over'); });
    });
    zone.addEventListener('drop', function (event) {
      if (!event.dataTransfer || event.dataTransfer.files.length === 0) return;
      input.files = event.dataTransfer.files;
      show();
    });
  });

  // Snippet import preview: the choice for existing snippets ticks or unticks every row that would replace one.
  document.querySelectorAll('input[data-import-conflicts]').forEach(function (radio) {
    radio.addEventListener('change', function () {
      const replace = radio.dataset.importConflicts === 'replace';
      document.querySelectorAll('input[data-conflict]').forEach(function (box) { box.checked = replace; });
    });
  });

  // Copy buttons: <button data-copy="id-of-element">
  document.querySelectorAll('[data-copy]').forEach(function (button) {
    button.addEventListener('click', function () {
      const source = document.getElementById(button.dataset.copy);
      if (!source || !navigator.clipboard) return;
      navigator.clipboard.writeText(source.textContent).then(function () {
        const label = button.textContent;
        button.textContent = 'Copied';
        setTimeout(function () { button.textContent = label; }, 1500);
      });
    });
  });

  // Upload with progress: <form data-upload> with a .progress > span inside.
  document.querySelectorAll('form[data-upload]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      const bar = form.querySelector('.progress > span');
      const button = form.querySelector('button[type=submit]');
      const request = new XMLHttpRequest();
      request.open('POST', form.action);
      request.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable && bar) bar.style.width = Math.round(e.loaded * 100 / e.total) + '%';
      });
      request.addEventListener('load', function () {
        // Success ends in a redirect to the listing. Anything else is an error page: show its message at the form.
        if (request.status < 400) {
          window.location.href = request.responseURL || window.location.href;
          return;
        }
        const page = new DOMParser().parseFromString(request.responseText, 'text/html');
        const notice = page.querySelector('.notice.error');
        let box = form.querySelector('.notice');
        if (!box) {
          box = document.createElement('div');
          form.prepend(box);
        }
        box.className = 'notice error';
        box.textContent = notice ? notice.textContent : 'Upload failed (HTTP ' + request.status + ')';
        if (bar) bar.style.width = '0';
        if (button) button.disabled = false;
      });
      request.addEventListener('error', function () {
        if (button) button.disabled = false;
        window.alert('Upload failed');
      });
      if (button) button.disabled = true;
      request.send(new FormData(form));
    });
  });
})();
