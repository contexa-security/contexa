/**
 * Contexa Component Include Loader
 * Loads shared components (header, footer, sidebar) via fetch
 */
(function () {
  'use strict';

  /**
   * Resolves a relative path from the current page to the site root.
   * Uses the data-root attribute on the script tag or calculates from depth.
   */
  function getSiteRoot() {
    var scripts = document.querySelectorAll('script[data-root]');
    for (var i = 0; i < scripts.length; i++) {
      if (scripts[i].src.indexOf('include.js') !== -1) {
        return scripts[i].getAttribute('data-root') || '';
      }
    }
    return '';
  }

  var siteRoot = getSiteRoot();

  /**
   * Loads all elements with data-include attribute
   */
  function loadIncludes() {
    var elements = document.querySelectorAll('[data-include]');
    var promises = [];

    elements.forEach(function (el) {
      var path = el.getAttribute('data-include');
      if (!path) return;

      // Resolve path relative to site root
      var resolvedPath = siteRoot + path;

      var promise = fetch(resolvedPath)
        .then(function (response) {
          if (!response.ok) {
            throw new Error('Failed to load: ' + resolvedPath + ' (' + response.status + ')');
          }
          return response.text();
        })
        .then(function (html) {
          el.innerHTML = html;
          el.setAttribute('data-loaded', 'true');

          // Process any links in the loaded content to be root-relative
          processLinks(el);
        })
        .catch(function (error) {
          console.error('[Contexa] Include error:', error.message);
        });

      promises.push(promise);
    });

    // After all includes are loaded, initialize dependent scripts
    Promise.all(promises).then(function () {
      document.dispatchEvent(new CustomEvent('contexa:includes-loaded'));
    });
  }

  /**
   * Adjusts relative links in included content based on site root
   */
  function processLinks(container) {
    if (!siteRoot) return;

    var links = container.querySelectorAll('a[href]');
    links.forEach(function (link) {
      var href = link.getAttribute('href');
      // Only process internal links starting with /
      if (href && href.charAt(0) === '/' && href.indexOf('//') !== 0) {
        link.setAttribute('href', siteRoot + href);
      }
    });
  }

  // Load includes when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadIncludes);
  } else {
    loadIncludes();
  }
})();
