const form = document.querySelector("[data-testid='scan-form']");
if (form) {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (button) {
      button.classList.add("is-loading");
      button.querySelector("span").textContent = "Идёт анализ";
    }
  });

  const injectionProfile = form.querySelector("[data-injection-profile]");
  if (injectionProfile) {
    injectionProfile.addEventListener("change", () => {
      if (!injectionProfile.checked) return;
      const activeMode = form.querySelector("input[name='active_mode']");
      if (activeMode) activeMode.checked = true;
      ["wapiti", "sqlmap", "burp"].forEach((tool) => {
        const checkbox = form.querySelector(`input[name='tools'][value='${tool}']`);
        if (checkbox) checkbox.checked = true;
      });
    });
  }
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    const name = button.dataset.tab;
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    const panel = document.getElementById(`tab-${name}`);
    if (panel) panel.classList.add("active");
  });
});
