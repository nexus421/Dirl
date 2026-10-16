// Small progressive enhancements for every page. Everything works without it, just with fewer comforts.
// Loaded as a file because the CSP forbids inline scripts.
'use strict';
(function () {
  // Confirmation before destructive actions: <form data-confirm="Delete this host?">
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
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
