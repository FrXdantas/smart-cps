// SMART ESBMC/JBMC — bootstrap de autenticação na SPA.
// Roda antes de app.js; valida sessão e popula o navbar (usuário, sair, link admin).

(async () => {
  try {
    const me = await api.me();
    window.__currentUser = me;

    const label = document.getElementById("user-label");
    if (label) {
      label.innerHTML =
        me.login +
        ' <span class="badge bg-light text-dark ms-1">' + me.role + '</span>';
    }

    if (me.role === "admin") {
      const link = document.getElementById("link-admin");
      if (link) link.classList.remove("d-none");
    } else {
      // user comum: oculta o botão "Procurar no servidor" — vaza a estrutura do servidor.
      const browseBtn = document.getElementById("btn-browse");
      if (browseBtn) browseBtn.classList.add("d-none");
    }

    const btn = document.getElementById("btn-logout");
    if (btn) {
      btn.addEventListener("click", async () => {
        try { await api.logout(); } catch (_) {}
        location.href = "/login.html";
      });
    }
  } catch (e) {
    // api.me() já redireciona em 401; em outros erros, só registra.
    console.warn("Falha no bootstrap de auth:", e);
  }
})();
