'use strict';
document.querySelectorAll('[data-confirm]').forEach(form => form.addEventListener('submit', event => {
  if (!window.confirm(form.dataset.confirm)) event.preventDefault();
}));
document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
  const input = document.getElementById(button.dataset.copy);
  try { await navigator.clipboard.writeText(input.value); button.textContent = 'Copied'; }
  catch { input.focus(); input.select(); button.textContent = 'Selected — copy with your keyboard'; }
}));
document.querySelectorAll('[data-copy-code]').forEach(button => button.addEventListener('click', async () => {
  const block = document.getElementById(button.dataset.copyCode);
  if (!block) return;
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(block.textContent.trim());
    button.textContent = 'Copied';
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(block);
    selection.removeAllRanges();
    selection.addRange(range);
    button.textContent = 'Selected — copy with your keyboard';
  }
  window.setTimeout(() => { button.textContent = original; }, 1800);
}));

// Small dependency-free syntax highlighter for the embedded documentation.
// It creates text nodes and spans instead of injecting HTML.
document.querySelectorAll('code[data-language]').forEach(block => {
  const language = block.dataset.language;
  const keywords = {
    javascript: 'const|let|var|await|async|while|if|else|throw|new|return|import|from|function',
    python: 'import|from|as|with|while|if|elif|else|raise|def|return|in|not|and|or',
    go: 'package|import|func|defer|if|else|for|range|return|var|const|type|struct|map',
    bash: 'curl|cat|export',
  }[language] || '';
  const comment = ['javascript', 'go'].includes(language)
    ? String.raw`\/\/[^\n]*|\/\*[\s\S]*?\*\/`
    : ['python', 'bash', 'env', 'yaml'].includes(language) ? String.raw`#[^\n]*` : String.raw`(?!x)x`;
  const property = language === 'env'
    ? String.raw`^[ \t]*[A-Z_][A-Z0-9_]*(?==)`
    : language === 'yaml' ? String.raw`^[ \t]*[A-Za-z_][\w-]*(?=\s*:)` : String.raw`(?!x)x`;
  const patterns = [
    ['comment', comment],
    ['string', String.raw`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\x60(?:\\.|[^\x60\\])*\x60`],
    ['variable', String.raw`\$\{?[A-Za-z_][A-Za-z0-9_.]*\}?`],
    ['flag', String.raw`--[A-Za-z][A-Za-z-]*`],
    ['property', property],
    ['keyword', keywords ? String.raw`\b(?:${keywords})\b` : String.raw`(?!x)x`],
    ['number', String.raw`\b\d+(?:\.\d+)?\b`],
  ];
  const matcher = new RegExp(patterns.map(([name, pattern]) => `(?<${name}>${pattern})`).join('|'), 'gm');
  const source = block.textContent;
  const fragment = document.createDocumentFragment();
  let offset = 0;
  for (const match of source.matchAll(matcher)) {
    fragment.append(document.createTextNode(source.slice(offset, match.index)));
    const kind = Object.keys(match.groups).find(name => match.groups[name] !== undefined);
    const token = document.createElement('span');
    token.className = `syntax-${kind}`;
    token.textContent = match[0];
    fragment.append(token);
    offset = match.index + match[0].length;
  }
  fragment.append(document.createTextNode(source.slice(offset)));
  block.replaceChildren(fragment);
});

const renderJSON = (block, source) => {
  const matcher = /("(?:\\.|[^"\\])*")(?=\s*:)|"(?:\\.|[^"\\])*"|-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b|\b(?:true|false|null)\b|[{}[\],:]/gi;
  const fragment = document.createDocumentFragment();
  let offset = 0;
  for (const match of source.matchAll(matcher)) {
    fragment.append(document.createTextNode(source.slice(offset, match.index)));
    const token = document.createElement('span');
    if (match[1] !== undefined) token.className = 'json-key';
    else if (match[0].startsWith('"')) token.className = 'json-string';
    else if (/^(true|false|null)$/i.test(match[0])) token.className = 'json-literal';
    else if (/^-?\d/.test(match[0])) token.className = 'json-number';
    else token.className = 'json-punctuation';
    token.textContent = match[0];
    fragment.append(token);
    offset = match.index + match[0].length;
  }
  fragment.append(document.createTextNode(source.slice(offset)));
  block.replaceChildren(fragment);
};

document.querySelectorAll('textarea[data-json-editor]').forEach(textarea => {
  const editor = document.createElement('div');
  editor.className = 'json-editor';
  const stage = document.createElement('div');
  stage.className = 'json-editor-stage';
  const highlight = document.createElement('pre');
  highlight.className = 'json-editor-highlight';
  highlight.setAttribute('aria-hidden', 'true');
  const code = document.createElement('code');
  highlight.append(code);
  const toolbar = document.createElement('div');
  toolbar.className = 'json-editor-toolbar';
  const status = document.createElement('span');
  status.className = 'json-status';
  status.setAttribute('aria-live', 'polite');
  const format = document.createElement('button');
  format.type = 'button';
  format.className = 'small json-format';
  format.textContent = 'Format JSON';
  textarea.before(editor);
  editor.append(stage, toolbar);
  stage.append(highlight, textarea);
  toolbar.append(status, format);

  const update = () => {
    const source = textarea.value;
    renderJSON(code, source || textarea.placeholder || '');
    highlight.classList.toggle('is-placeholder', !source);
    let message = 'Enter a JSON object';
    let valid = false;
    if (source.trim()) {
      try {
        const parsed = JSON.parse(source);
        const object = parsed && typeof parsed === 'object' && !Array.isArray(parsed);
        const strings = object && Object.values(parsed).every(value => typeof value === 'string');
        if (!object) message = 'The root value must be an object';
        else if (!strings) message = 'Every value must be a string';
        else {
          valid = Object.keys(parsed).length > 0;
          message = valid ? `Valid JSON · ${Object.keys(parsed).length} key${Object.keys(parsed).length === 1 ? '' : 's'}` : 'Add at least one key';
        }
      } catch (error) {
        message = `Invalid JSON · ${error.message.replace(/^JSON\.parse: /, '')}`;
      }
    }
    status.textContent = message;
    status.classList.toggle('valid', valid);
    status.classList.toggle('invalid', Boolean(source.trim()) && !valid);
    textarea.setCustomValidity(valid ? '' : message);
  };
  const syncScroll = () => {
    highlight.scrollTop = textarea.scrollTop;
    highlight.scrollLeft = textarea.scrollLeft;
  };
  textarea.addEventListener('input', update);
  textarea.addEventListener('scroll', syncScroll);
  format.addEventListener('click', () => {
    try {
      textarea.value = JSON.stringify(JSON.parse(textarea.value), null, 2);
      update();
      textarea.focus();
    } catch {
      textarea.reportValidity();
    }
  });
  update();
});
document.querySelectorAll('[data-reveal]').forEach(button => button.addEventListener('click', () => {
  const editor = document.getElementById(button.dataset.reveal);
  editor.hidden = !editor.hidden;
  document.getElementById('masked-values').hidden = !editor.hidden;
  document.getElementById('save-version').hidden = editor.hidden;
  button.textContent = editor.hidden ? 'Reveal & edit values' : 'Hide values';
}));
if (document.querySelector('[data-live]')) {
  const events = new EventSource('/admin/events');
  const status = document.getElementById('live-status');
  events.onopen = () => { if (status) status.textContent = '· Connected'; };
  events.onerror = () => { if (status) status.textContent = '· Reconnecting…'; };
  events.addEventListener('approvals', () => window.location.reload());
  window.addEventListener('pagehide', () => events.close());
}
// Avoid displaying cached tokens or plaintext when returning with browser Back.
window.addEventListener('pageshow', event => { if (event.persisted) window.location.reload(); });

const themeMedia = window.matchMedia('(prefers-color-scheme: dark)');
const applyTheme = choice => {
  const dark = choice === 'dark' || (choice === 'system' && themeMedia.matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.documentElement.dataset.themeChoice = choice;
  document.querySelectorAll('[data-theme-toggle]').forEach(button => {
    button.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
    button.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
    const icon = button.querySelector('[data-theme-icon]');
    if (icon) icon.textContent = dark ? '☀' : '☾';
  });
};
const savedTheme = document.documentElement.dataset.themeChoice || 'system';
applyTheme(savedTheme);
document.querySelectorAll('[data-theme-toggle]').forEach(button => button.addEventListener('click', () => {
  const choice = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('lockgate-theme', choice); } catch (_) {}
  applyTheme(choice);
}));
themeMedia.addEventListener('change', () => {
  if ((document.documentElement.dataset.themeChoice || 'system') === 'system') applyTheme('system');
});

document.querySelectorAll('[data-code-tabs]').forEach(tabs => {
  const buttons = [...tabs.querySelectorAll('[role="tab"]')];
  const select = button => {
    buttons.forEach(item => {
      const active = item === button;
      item.setAttribute('aria-selected', String(active));
      item.tabIndex = active ? 0 : -1;
      const panel = document.getElementById(item.getAttribute('aria-controls'));
      if (panel) panel.hidden = !active;
    });
  };
  buttons.forEach((button, index) => {
    button.addEventListener('click', () => select(button));
    button.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
      if (event.key === 'ArrowLeft') next = (index - 1 + buttons.length) % buttons.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = buttons.length - 1;
      select(buttons[next]);
      buttons[next].focus();
    });
  });
});
