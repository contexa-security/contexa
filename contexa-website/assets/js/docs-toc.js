/**
 * Contexa Documentation Table of Contents
 * Auto-generates an "On This Page" navigation from h2/h3 headings
 * in the docs content area.
 */
(function () {
  'use strict';

  var initialized = false;

  function init() {
    if (initialized) return;
    initialized = true;
    var content = document.querySelector('.docs-content-inner');
    if (!content) return;

    var headings = content.querySelectorAll('h2[id], h3[id]');
    if (headings.length < 3) return; // Only show TOC for pages with 3+ sections

    // Build TOC
    var toc = document.createElement('nav');
    toc.className = 'docs-toc';
    toc.setAttribute('aria-label', 'On this page');

    var title = document.createElement('div');
    title.className = 'docs-toc-title';
    title.textContent = 'On This Page';

    var toggle = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    toggle.setAttribute('class', 'docs-toc-toggle');
    toggle.setAttribute('viewBox', '0 0 12 12');
    toggle.setAttribute('fill', 'none');
    toggle.setAttribute('stroke', 'currentColor');
    toggle.setAttribute('stroke-width', '2');
    toggle.setAttribute('stroke-linecap', 'round');
    var togglePath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    togglePath.setAttribute('d', 'M3 5L6 8L9 5');
    toggle.appendChild(togglePath);
    title.appendChild(toggle);

    var list = document.createElement('ul');
    list.className = 'docs-toc-list';

    headings.forEach(function (heading) {
      var li = document.createElement('li');
      li.className = heading.tagName === 'H3' ? 'docs-toc-item docs-toc-sub' : 'docs-toc-item';

      var link = document.createElement('a');
      link.href = '#' + heading.id;
      link.className = 'docs-toc-link';
      link.textContent = heading.textContent.replace(/\s*#\s*$/, '');

      link.addEventListener('click', function (e) {
        e.preventDefault();
        heading.scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.replaceState(null, '', '#' + heading.id);
      });

      li.appendChild(link);
      list.appendChild(li);
    });

    toc.appendChild(title);
    toc.appendChild(list);

    // Insert after page header
    var pageHeader = content.querySelector('.docs-page-header');
    if (pageHeader && pageHeader.nextSibling) {
      pageHeader.parentNode.insertBefore(toc, pageHeader.nextSibling);
    } else {
      content.insertBefore(toc, content.firstChild);
    }

    // Mobile toggle
    title.addEventListener('click', function () {
      toc.classList.toggle('collapsed');
    });

    // Start collapsed on mobile
    if (window.innerWidth <= 768) {
      toc.classList.add('collapsed');
    }

    // Scroll spy: highlight current section
    initScrollSpy(headings, list);
  }

  function initScrollSpy(headings, list) {
    var links = list.querySelectorAll('.docs-toc-link');
    var ticking = false;

    function update() {
      var scrollTop = window.scrollY;
      var offset = 120;
      var currentIndex = -1;

      for (var i = 0; i < headings.length; i++) {
        if (headings[i].offsetTop - offset <= scrollTop) {
          currentIndex = i;
        }
      }

      links.forEach(function (link, i) {
        if (i === currentIndex) {
          link.classList.add('active');
        } else {
          link.classList.remove('active');
        }
      });
    }

    window.addEventListener('scroll', function () {
      if (!ticking) {
        requestAnimationFrame(function () {
          update();
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });

    // Initial highlight
    update();
  }

  // Initialize after content is ready
  document.addEventListener('contexa:includes-loaded', init);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(init, 250);
    });
  }
})();
