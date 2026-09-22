'use strict';
(() => {
  let theme = 'system';
  try { theme = localStorage.getItem('lockgate-theme') || 'system'; } catch (_) {}
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.documentElement.dataset.themeChoice = theme;
})();
