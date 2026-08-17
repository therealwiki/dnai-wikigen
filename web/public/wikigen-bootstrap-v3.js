(() => {
  "use strict";

  const state = document.documentElement.dataset;
  state.wikigenBootstrap = "v3";

  // Use one canonical browser origin. The apex has historical per-origin
  // client state in some browsers; www is the clean Pages origin. Preserve the
  // complete URL so hash-routed product surfaces and query context survive.
  if (window.location.hostname === "wikigen.me") {
    const target = new URL(window.location.href);
    target.hostname = "www.wikigen.me";
    state.wikigenCanonicalRedirect = "www";
    window.location.replace(target.toString());
    return;
  }

  if (!("serviceWorker" in navigator)) {
    state.wikigenServiceWorker = "unsupported";
    return;
  }
  if (!navigator.serviceWorker.controller) {
    state.wikigenServiceWorker = "clear";
    return;
  }

  // Wikigen does not install a service worker. A controller here can only be
  // residue from an older deployment, and may keep serving obsolete modules.
  // Retire registrations without clearing cookies, wallet state, or storage.
  state.wikigenServiceWorker = "retiring";
  navigator.serviceWorker.getRegistrations()
    .then((registrations) => {
      if (registrations.length === 0) {
        state.wikigenServiceWorker = "controller-without-registration";
        return false;
      }
      return Promise.all(registrations.map((registration) => registration.unregister()))
        .then(() => true);
    })
    .then((retired) => {
      if (!retired) return;
      state.wikigenServiceWorker = "retired";
      window.location.reload();
    })
    .catch(() => {
      state.wikigenServiceWorker = "retirement-failed";
    });
})();
