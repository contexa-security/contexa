/**
 * Contexa Code Block Enhancer
 * Handles: Prism.js initialization, copy-to-clipboard, language labels
 */
(function () {
  'use strict';

  var initialized = false;

  function init() {
    if (initialized) return;
    initialized = true;
    loadPrism(function () {
      enhanceCodeBlocks();
    });
  }

  /**
   * Dynamically loads Prism.js core + Java language support
   */
  function loadPrism(callback) {
    if (window.Prism) { callback(); return; }

    var script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js';
    script.onload = function () {
      // Load Java language component
      var javaScript = document.createElement('script');
      javaScript.src = 'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-java.min.js';
      javaScript.onload = function () {
        // Load additional languages
        var langs = ['yaml', 'bash', 'json', 'markup', 'properties'];
        var loaded = 0;
        langs.forEach(function (lang) {
          var s = document.createElement('script');
          s.src = 'https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-' + lang + '.min.js';
          s.onload = s.onerror = function () {
            loaded++;
            if (loaded >= langs.length) callback();
          };
          document.head.appendChild(s);
        });
      };
      document.head.appendChild(javaScript);
    };
    script.onerror = function () { callback(); };
    document.head.appendChild(script);
  }

  /**
   * Wraps all pre>code blocks with the code-block container
   * and adds language label + copy button
   */
  function enhanceCodeBlocks() {
    var codeBlocks = document.querySelectorAll('pre > code[class*="language-"]');

    codeBlocks.forEach(function (codeEl) {
      var pre = codeEl.parentElement;

      // Skip already enhanced blocks
      if (pre.parentElement && pre.parentElement.classList.contains('code-block')) return;

      // Detect language from class
      var langClass = Array.from(codeEl.classList).find(function (c) {
        return c.indexOf('language-') === 0;
      });
      var lang = langClass ? langClass.replace('language-', '') : '';
      var langDisplay = getLanguageDisplay(lang);

      // Create wrapper
      var wrapper = document.createElement('div');
      wrapper.className = 'code-block';

      // Create header
      var header = document.createElement('div');
      header.className = 'code-block-header';

      var langLabel = document.createElement('span');
      langLabel.className = 'code-block-lang';
      langLabel.textContent = langDisplay;

      var copyBtn = document.createElement('button');
      copyBtn.className = 'code-copy-btn';
      copyBtn.type = 'button';
      copyBtn.setAttribute('aria-label', 'Copy code');
      copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span>Copy</span>';

      header.appendChild(langLabel);
      header.appendChild(copyBtn);

      // Wrap the pre element
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(header);
      wrapper.appendChild(pre);

      // Copy button handler
      copyBtn.addEventListener('click', function () {
        copyToClipboard(codeEl.textContent, copyBtn);
      });
    });

    // Also handle pre-built code-block containers
    var existingBlocks = document.querySelectorAll('.code-block');
    existingBlocks.forEach(function (block) {
      var copyBtn = block.querySelector('.code-copy-btn');
      var codeEl = block.querySelector('code');
      if (copyBtn && codeEl && !copyBtn.hasAttribute('data-initialized')) {
        copyBtn.setAttribute('data-initialized', 'true');
        copyBtn.addEventListener('click', function () {
          copyToClipboard(codeEl.textContent, copyBtn);
        });
      }
    });

    // Run Prism highlighting if available
    if (typeof Prism !== 'undefined') {
      Prism.highlightAll();
    }
  }

  /**
   * Copies text to clipboard and updates button state
   */
  function copyToClipboard(text, button) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        showCopied(button);
      }).catch(function () {
        fallbackCopy(text, button);
      });
    } else {
      fallbackCopy(text, button);
    }
  }

  /**
   * Fallback copy method using textarea
   */
  function fallbackCopy(text, button) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      showCopied(button);
    } catch (e) {
      console.error('[Contexa] Copy failed:', e);
    }
    document.body.removeChild(textarea);
  }

  /**
   * Shows copied state on button
   */
  function showCopied(button) {
    var span = button.querySelector('span');
    var originalText = span ? span.textContent : '';

    button.classList.add('copied');
    if (span) span.textContent = 'Copied!';

    button.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg><span>Copied!</span>';

    setTimeout(function () {
      button.classList.remove('copied');
      button.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span>Copy</span>';
    }, 2000);
  }

  /**
   * Maps language identifiers to display names
   */
  function getLanguageDisplay(lang) {
    var map = {
      'java': 'Java',
      'kotlin': 'Kotlin',
      'groovy': 'Groovy',
      'gradle': 'Gradle',
      'xml': 'XML',
      'yaml': 'YAML',
      'yml': 'YAML',
      'json': 'JSON',
      'properties': 'Properties',
      'bash': 'Shell',
      'shell': 'Shell',
      'sh': 'Shell',
      'sql': 'SQL',
      'html': 'HTML',
      'css': 'CSS',
      'javascript': 'JavaScript',
      'js': 'JavaScript',
      'typescript': 'TypeScript',
      'ts': 'TypeScript',
      'text': 'Text',
      'plaintext': 'Text',
      'http': 'HTTP',
      'markdown': 'Markdown',
      'md': 'Markdown'
    };
    return map[lang.toLowerCase()] || lang.toUpperCase();
  }

  // Initialize when includes are loaded
  document.addEventListener('contexa:includes-loaded', function () {
    setTimeout(init, 50);
  });

  // Fallback
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(init, 200);
    });
  } else {
    setTimeout(init, 200);
  }
})();
