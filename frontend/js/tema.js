// Tema claro/escuro. Segue o sistema até a pessoa escolher; a escolha fica só
// neste navegador. Carregado no <head> para a página não piscar no tema errado.
(function () {
  const CHAVE = "smart-tema";
  const raiz = document.documentElement;

  let salvo = null;
  try { salvo = localStorage.getItem(CHAVE); } catch { /* navegador sem storage */ }
  const doSistema = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  raiz.setAttribute("data-bs-theme", salvo || doSistema);

  function rotular() {
    const escuro = raiz.getAttribute("data-bs-theme") === "dark";
    document.querySelectorAll("[data-tema-btn]").forEach((b) => {
      b.textContent = escuro ? "Tema claro" : "Tema escuro";
      b.setAttribute("aria-pressed", String(escuro));
    });
  }

  function alternar() {
    const novo = raiz.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
    raiz.setAttribute("data-bs-theme", novo);
    try { localStorage.setItem(CHAVE, novo); } catch { /* ignora */ }
    rotular();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-tema-btn]").forEach((b) => b.addEventListener("click", alternar));
    rotular();
  });
})();
