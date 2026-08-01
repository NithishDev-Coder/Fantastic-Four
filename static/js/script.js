document.addEventListener("DOMContentLoaded", () => {
  const root = document.documentElement;
  const themeToggle = document.getElementById("theme-toggle");
  const storedTheme = window.localStorage.getItem("reconguard-theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initialTheme = storedTheme || (prefersDark ? "dark" : "light");

  const applyTheme = (theme) => {
    root.setAttribute("data-theme", theme);
    root.style.colorScheme = theme;

    if (themeToggle) {
      const isDark = theme === "dark";
      themeToggle.setAttribute("aria-pressed", String(isDark));
      const label = themeToggle.querySelector(".theme-toggle-label");
      const icon = themeToggle.querySelector(".theme-toggle-icon");
      if (label) label.textContent = isDark ? "Light" : "Dark";
      if (icon) icon.textContent = isDark ? "☀︎" : "☾";
    }
  };

  applyTheme(initialTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(nextTheme);
      window.localStorage.setItem("reconguard-theme", nextTheme);
    });
  }

  // Animate the risk gauge from 0 up to its actual score on load.
  const gaugeFill = document.querySelector(".gauge-fill");
  if (gaugeFill) {
    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    const score = Math.min(parseFloat(gaugeFill.dataset.score || "0"), 100);
    const targetOffset = circumference * (1 - score / 100);

    gaugeFill.style.strokeDasharray = `${circumference}`;
    gaugeFill.style.strokeDashoffset = `${circumference}`;

    requestAnimationFrame(() => {
      gaugeFill.style.transition = "stroke-dashoffset 1.1s ease-out";
      gaugeFill.style.strokeDashoffset = `${targetOffset}`;
    });
  }

  // Disable the scan button and swap its label once a scan is submitted,
  // so a slow scan doesn't invite someone to click it three more times.
  const form = document.getElementById("scan-form");
  const button = document.getElementById("scan-button");
  if (form && button) {
    form.addEventListener("submit", () => {
      button.disabled = true;
      const label = button.querySelector(".btn-label");
      if (label) label.textContent = "Scanning…";
    });
  }
});
