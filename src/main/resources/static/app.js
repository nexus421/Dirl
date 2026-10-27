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
