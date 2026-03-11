/**
 * Contexa Documentation Search
 * Client-side search that filters sidebar links by keyword.
 * Injects a search input at the top of the docs sidebar.
 */
(function () {
  'use strict';

  var initialized = false;

  function init() {
    if (initialized) return;
    initialized = true;
    var sidebar = document.querySelector('.docs-sidebar');
    if (!sidebar) return;

    // Build search input
    var wrapper = document.createElement('div');
    wrapper.className = 'sidebar-search';

    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'sidebar-search-input';
    input.placeholder = 'Search docs...';
    input.setAttribute('aria-label', 'Search documentation');

    var icon = document.createElement('span');
    icon.className = 'sidebar-search-icon';
    icon.innerHTML = '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8.5" cy="8.5" r="5.5"/><line x1="13" y1="13" x2="18" y2="18"/></svg>';

    var clear = document.createElement('button');
    clear.className = 'sidebar-search-clear';
    clear.type = 'button';
    clear.setAttribute('aria-label', 'Clear search');
    clear.innerHTML = '&times;';
    clear.style.display = 'none';

    wrapper.appendChild(icon);
    wrapper.appendChild(input);
    wrapper.appendChild(clear);

    sidebar.insertBefore(wrapper, sidebar.firstChild);

    // Collect all searchable items
    var sections = sidebar.querySelectorAll('.sidebar-section');
    var items = [];

    sections.forEach(function (section) {
      var links = section.querySelectorAll('.sidebar-link');
      links.forEach(function (link) {
        items.push({
          el: link.closest('li') || link,
          text: (link.textContent || '').toLowerCase(),
          section: section
        });
      });
    });

    // Search logic
    var debounceTimer;
    input.addEventListener('input', function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        performSearch(input.value.trim().toLowerCase(), items, sections, clear);
      }, 150);
    });

    clear.addEventListener('click', function () {
      input.value = '';
      performSearch('', items, sections, clear);
      input.focus();
    });

    // Keyboard shortcut: Ctrl+K or /
    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey && e.key === 'k') || (e.key === '/' && !isInputFocused())) {
        e.preventDefault();
        input.focus();
        input.select();
      }
      if (e.key === 'Escape' && document.activeElement === input) {
        input.value = '';
        performSearch('', items, sections, clear);
        input.blur();
      }
    });
  }

  function isInputFocused() {
    var el = document.activeElement;
    return el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
  }

  function performSearch(query, items, sections, clearBtn) {
    clearBtn.style.display = query ? 'block' : 'none';

    if (!query) {
      // Restore all items and sections
      items.forEach(function (item) {
        item.el.style.display = '';
      });
      sections.forEach(function (section) {
        section.style.display = '';
        section.classList.remove('search-expanded');
      });
      return;
    }

    var terms = query.split(/\s+/);

    items.forEach(function (item) {
      var match = terms.every(function (term) {
        return item.text.indexOf(term) !== -1;
      });
      item.el.style.display = match ? '' : 'none';
    });

    // Show/hide sections based on whether they have visible items
    sections.forEach(function (section) {
      var links = section.querySelectorAll('.sidebar-link');
      var hasVisible = false;
      links.forEach(function (link) {
        var li = link.closest('li') || link;
        if (li.style.display !== 'none') hasVisible = true;
      });
      section.style.display = hasVisible ? '' : 'none';

      // Expand matching sections during search
      if (hasVisible && section.classList.contains('collapsed')) {
        section.classList.add('search-expanded');
        section.classList.remove('collapsed');
        var sectionLinks = section.querySelector('.sidebar-links');
        if (sectionLinks) {
          sectionLinks.style.maxHeight = sectionLinks.scrollHeight + 'px';
          sectionLinks.style.opacity = '1';
        }
      }
    });
  }

  // Initialize after sidebar is ready
  document.addEventListener('contexa:includes-loaded', init);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(init, 200);
    });
  }
})();
