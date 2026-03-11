/**
 * Contexa Documentation Sidebar Controller
 * Handles: SPA content routing, active state, section collapse/expand,
 *          mobile toggle, scroll tracking
 */
(function () {
  'use strict';

  var isNavigating = false;
  var initialized = false;

  function init() {
    if (initialized) return;
    initialized = true;
    initActiveState();
    initSectionHeights();
    initSectionToggle();
    initMobileSidebar();
    initScrollTracking();
    initSpaRouting();
  }

  // ─── SPA Content Routing ───

  /**
   * Intercepts sidebar link clicks and loads content without full page reload.
   * Falls back to normal navigation on fetch failure (e.g. file:// protocol).
   */
  function initSpaRouting() {
    var sidebar = document.querySelector('.docs-sidebar');
    if (!sidebar) return;

    // Skip SPA routing for file:// protocol (fetch won't work)
    if (window.location.protocol === 'file:') return;

    sidebar.addEventListener('click', function (e) {
      var link = e.target.closest('.sidebar-link');
      if (!link) return;

      var href = link.getAttribute('href');
      if (!href || href.startsWith('#') || href.startsWith('http')) return;

      // Prevent navigation if already loading
      if (isNavigating) {
        e.preventDefault();
        return;
      }

      e.preventDefault();
      navigateTo(href);
    });

    // Handle browser back/forward buttons
    window.addEventListener('popstate', function () {
      loadPage(window.location.href, false);
    });
  }

  /**
   * Navigate to a new docs page via SPA routing
   */
  function navigateTo(href) {
    // Resolve relative URL to absolute
    var url = new URL(href, window.location.href).href;

    // Don't navigate to the same page
    if (url === window.location.href) return;

    loadPage(url, true);
  }

  /**
   * Fetch page HTML and replace only the content area
   */
  function loadPage(url, pushState) {
    isNavigating = true;

    // Add loading indicator
    var content = document.querySelector('.docs-content');
    if (content) content.style.opacity = '0.5';

    fetch(url)
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.text();
      })
      .then(function (html) {
        // Parse the fetched HTML
        var parser = new DOMParser();
        var doc = parser.parseFromString(html, 'text/html');

        // Extract the new content
        var newContentInner = doc.querySelector('.docs-content-inner');
        var currentContentInner = document.querySelector('.docs-content-inner');

        if (!newContentInner || !currentContentInner) {
          // Fallback: full page navigation
          window.location.href = url;
          return;
        }

        // Replace content
        currentContentInner.innerHTML = newContentInner.innerHTML;

        // Update page title
        var newTitle = doc.querySelector('title');
        if (newTitle) document.title = newTitle.textContent;

        // Update URL in address bar
        if (pushState) {
          history.pushState(null, '', url);
        }

        // Scroll to top of content
        window.scrollTo(0, 0);

        // Restore opacity
        if (content) content.style.opacity = '';

        // Re-run code highlighting if Prism is available
        if (window.Prism) {
          Prism.highlightAllUnder(currentContentInner);
        }

        // Update sidebar active state for new URL
        updateSidebarActive();

        // Re-init scroll tracking for new headings
        initScrollTracking();

        isNavigating = false;
      })
      .catch(function () {
        // On failure, fall back to normal navigation
        isNavigating = false;
        if (content) content.style.opacity = '';
        window.location.href = url;
      });
  }

  /**
   * Resolves a sidebar link's absolute URL for comparison.
   * Uses the DOM .href property which the browser resolves automatically.
   */
  function normalizeUrl(url) {
    return url.split('#')[0].split('?')[0].replace(/\.html$/, '');
  }

  function resolveUrl(link) {
    return normalizeUrl(link.href);
  }

  function currentUrl() {
    return normalizeUrl(window.location.href);
  }

  /**
   * Update sidebar active link based on current URL (after SPA navigation)
   */
  function updateSidebarActive() {
    var sidebar = document.querySelector('.docs-sidebar');
    if (!sidebar) return;

    var pageUrl = currentUrl();

    // Clear all active states
    sidebar.querySelectorAll('.sidebar-link.active').forEach(function (el) {
      el.classList.remove('active');
    });
    sidebar.querySelectorAll('.sidebar-section.has-active').forEach(function (el) {
      el.classList.remove('has-active');
    });

    var links = sidebar.querySelectorAll('.sidebar-link');
    var matched = false;

    links.forEach(function (link) {
      if (matched) return;

      if (resolveUrl(link) === pageUrl) {
        link.classList.add('active');
        matched = true;

        var section = link.closest('.sidebar-section');
        if (section) {
          section.classList.add('has-active');

          // Expand the section if collapsed
          if (section.classList.contains('collapsed')) {
            section.classList.remove('collapsed');
            var sectionLinks = section.querySelector('.sidebar-links');
            if (sectionLinks) {
              sectionLinks.style.maxHeight = sectionLinks.scrollHeight + 'px';
              sectionLinks.style.opacity = '1';
            }
          }
        }

        // Scroll active link into view
        setTimeout(function () {
          link.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }, 100);
      }
    });

    // Collapse sections without active link
    sidebar.querySelectorAll('.sidebar-section').forEach(function (section) {
      if (!section.classList.contains('has-active') && !section.classList.contains('collapsed')) {
        var sectionLinks = section.querySelector('.sidebar-links');
        if (sectionLinks) {
          sectionLinks.style.maxHeight = sectionLinks.scrollHeight + 'px';
          sectionLinks.offsetHeight;
          sectionLinks.style.maxHeight = '0';
          sectionLinks.style.opacity = '0';
        }
        section.classList.add('collapsed');
      }
    });
  }

  // ─── Active State ───

  /**
   * Highlights the current page link in the sidebar
   * and expands only its parent section
   */
  function initActiveState() {
    var sidebar = document.querySelector('.docs-sidebar');
    if (!sidebar) return;

    var pageUrl = currentUrl();
    var links = sidebar.querySelectorAll('.sidebar-link');
    var matched = false;

    links.forEach(function (link) {
      if (matched) return;

      if (resolveUrl(link) === pageUrl) {
        link.classList.add('active');
        matched = true;

        var section = link.closest('.sidebar-section');
        if (section) {
          section.classList.remove('collapsed');
          section.classList.add('has-active');
        }

        setTimeout(function () {
          link.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }, 300);
      }
    });

    var sections = sidebar.querySelectorAll('.sidebar-section');
    sections.forEach(function (section) {
      if (!section.classList.contains('has-active')) {
        section.classList.add('collapsed');
      }
    });
  }

  // ─── Section Heights & Toggle ───

  function setExpandedHeight(links) {
    if (!links) return;
    links.style.maxHeight = links.scrollHeight + 'px';
    links.style.opacity = '1';
  }

  function initSectionHeights() {
    var sidebar = document.querySelector('.docs-sidebar');
    if (!sidebar) return;

    var sections = sidebar.querySelectorAll('.sidebar-section');
    sections.forEach(function (section) {
      var links = section.querySelector('.sidebar-links');
      if (!links) return;

      if (section.classList.contains('collapsed')) {
        links.style.maxHeight = '0';
        links.style.opacity = '0';
      } else {
        links.style.maxHeight = links.scrollHeight + 'px';
        links.style.opacity = '1';
      }
    });
  }

  function initSectionToggle() {
    var sidebar = document.querySelector('.docs-sidebar');
    if (!sidebar) return;

    var titles = sidebar.querySelectorAll('.sidebar-section-title');
    titles.forEach(function (title) {
      title.addEventListener('click', function () {
        var section = title.closest('.sidebar-section');
        if (!section) return;

        var links = section.querySelector('.sidebar-links');
        if (!links) return;

        var isCollapsed = section.classList.contains('collapsed');

        if (isCollapsed) {
          section.classList.remove('collapsed');
          links.style.maxHeight = '0';
          links.offsetHeight;
          links.style.maxHeight = links.scrollHeight + 'px';
          links.style.opacity = '1';
        } else {
          links.style.maxHeight = links.scrollHeight + 'px';
          links.offsetHeight;
          links.style.maxHeight = '0';
          links.style.opacity = '0';
          section.classList.add('collapsed');
        }
      });

      title.setAttribute('role', 'button');
      title.setAttribute('tabindex', '0');
      title.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          title.click();
        }
      });
    });
  }

  // ─── Mobile Sidebar ───

  function initMobileSidebar() {
    var sidebar = document.querySelector('.docs-sidebar');
    var toggle = document.querySelector('.sidebar-toggle');
    var overlay = document.querySelector('.sidebar-overlay');
    if (!sidebar || !toggle) return;

    function openSidebar() {
      sidebar.classList.add('open');
      if (overlay) overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
      toggle.setAttribute('aria-expanded', 'true');
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      if (overlay) overlay.classList.remove('open');
      document.body.style.overflow = '';
      toggle.setAttribute('aria-expanded', 'false');
    }

    toggle.addEventListener('click', function () {
      var isOpen = sidebar.classList.contains('open');
      if (isOpen) closeSidebar();
      else openSidebar();
    });

    if (overlay) {
      overlay.addEventListener('click', closeSidebar);
    }

    var links = sidebar.querySelectorAll('.sidebar-link');
    links.forEach(function (link) {
      link.addEventListener('click', function () {
        if (window.innerWidth <= 1024) closeSidebar();
      });
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && sidebar.classList.contains('open')) {
        closeSidebar();
      }
    });
  }

  // ─── Scroll Tracking ───

  function initScrollTracking() {
    var headings = document.querySelectorAll('.docs-content h2[id], .docs-content h3[id]');
    if (headings.length === 0) return;

    var ticking = false;

    function onScroll() {
      if (!ticking) {
        requestAnimationFrame(function () {
          updateActiveHeading(headings);
          ticking = false;
        });
        ticking = true;
      }
    }

    window.addEventListener('scroll', onScroll, { passive: true });
  }

  function updateActiveHeading(headings) {
    var scrollTop = window.scrollY;
    var offset = 100;
    var current = null;

    for (var i = 0; i < headings.length; i++) {
      var heading = headings[i];
      if (heading.offsetTop - offset <= scrollTop) {
        current = heading;
      }
    }

    if (current) {
      var sidebar = document.querySelector('.docs-sidebar');
      if (sidebar) {
        var anchorLinks = sidebar.querySelectorAll('.sidebar-link[href*="#"]');
        anchorLinks.forEach(function (link) {
          var hash = link.getAttribute('href').split('#')[1];
          if (hash === current.id) {
            link.classList.add('active');
          } else {
            link.classList.remove('active');
          }
        });
      }
    }
  }

  // ─── Initialize ───

  document.addEventListener('contexa:includes-loaded', init);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(init, 150);
    });
  }
})();
