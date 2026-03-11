/**
 * Contexa Navigation Controller
 * Handles: scroll shadow, mobile menu, dropdown interactions, active state
 */
(function () {
  'use strict';

  function init() {
    initScrollShadow();
    initMobileMenu();
    initDropdowns();
    initActiveNavState();
  }

  /**
   * Adds shadow to header on scroll
   */
  function initScrollShadow() {
    var header = document.querySelector('.site-header');
    if (!header) return;

    var scrollThreshold = 10;

    function onScroll() {
      if (window.scrollY > scrollThreshold) {
        header.classList.add('scrolled');
      } else {
        header.classList.remove('scrolled');
      }
    }

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll(); // Initial check
  }

  /**
   * Mobile menu toggle
   */
  function initMobileMenu() {
    var toggle = document.querySelector('.mobile-menu-toggle');
    var mobileNav = document.querySelector('.mobile-nav');
    if (!toggle || !mobileNav) return;

    toggle.addEventListener('click', function () {
      var isOpen = mobileNav.classList.contains('open');

      if (isOpen) {
        mobileNav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      } else {
        mobileNav.classList.add('open');
        toggle.setAttribute('aria-expanded', 'true');
        document.body.style.overflow = 'hidden';
      }
    });

    // Close mobile menu on link click
    var mobileLinks = mobileNav.querySelectorAll('a');
    mobileLinks.forEach(function (link) {
      link.addEventListener('click', function () {
        mobileNav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      });
    });

    // Close on escape
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && mobileNav.classList.contains('open')) {
        mobileNav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      }
    });
  }

  /**
   * Desktop dropdown interactions
   * Uses hover with delay for better UX
   */
  function initDropdowns() {
    var navItems = document.querySelectorAll('.nav-item');
    var closeTimers = {};

    navItems.forEach(function (item, index) {
      var dropdown = item.querySelector('.nav-dropdown');
      if (!dropdown) return;

      item.addEventListener('mouseenter', function () {
        clearTimeout(closeTimers[index]);
        // Close other dropdowns
        navItems.forEach(function (other, otherIndex) {
          if (otherIndex !== index) {
            var otherDropdown = other.querySelector('.nav-dropdown');
            if (otherDropdown) {
              otherDropdown.style.opacity = '0';
              otherDropdown.style.visibility = 'hidden';
            }
          }
        });
        dropdown.style.opacity = '1';
        dropdown.style.visibility = 'visible';
      });

      item.addEventListener('mouseleave', function () {
        closeTimers[index] = setTimeout(function () {
          dropdown.style.opacity = '0';
          dropdown.style.visibility = 'hidden';
        }, 200);
      });

      // Keyboard accessibility
      var link = item.querySelector('.nav-link');
      if (link) {
        link.addEventListener('focus', function () {
          clearTimeout(closeTimers[index]);
          dropdown.style.opacity = '1';
          dropdown.style.visibility = 'visible';
        });
      }

      // Keep dropdown open when focused inside
      dropdown.addEventListener('focusin', function () {
        clearTimeout(closeTimers[index]);
      });

      dropdown.addEventListener('focusout', function (e) {
        if (!item.contains(e.relatedTarget)) {
          closeTimers[index] = setTimeout(function () {
            dropdown.style.opacity = '0';
            dropdown.style.visibility = 'hidden';
          }, 200);
        }
      });
    });

    // Close all dropdowns on Escape
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        navItems.forEach(function (item) {
          var dropdown = item.querySelector('.nav-dropdown');
          if (dropdown) {
            dropdown.style.opacity = '0';
            dropdown.style.visibility = 'hidden';
          }
        });
      }
    });
  }

  /**
   * Highlights the current page in the navigation
   */
  function initActiveNavState() {
    var currentPath = window.location.pathname;
    var navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(function (link) {
      var href = link.getAttribute('href');
      if (!href) return;

      // Normalize paths for comparison
      var linkPath = new URL(href, window.location.origin).pathname;

      if (currentPath === linkPath) {
        link.classList.add('active');
      } else if (currentPath.indexOf('/docs/') !== -1 && href.indexOf('/docs/') !== -1) {
        link.classList.add('active');
      }
    });
  }

  // Initialize when includes are loaded, or on DOM ready
  document.addEventListener('contexa:includes-loaded', init);

  // Fallback if includes aren't used
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(init, 100);
    });
  }
})();
