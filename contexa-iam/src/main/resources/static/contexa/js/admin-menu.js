document.addEventListener('DOMContentLoaded', function() {
    // Paths are compared without the servlet context path: the menu map below and the links name console paths.
    var withinApp = window.ContexaConsole ? window.ContexaConsole.pathWithinApp : function(value) { return value; };
    var path = withinApp(window.location.pathname);

    document.querySelectorAll('.main-menu-item.has-submenu').forEach(function(item) {
        var panel = item.querySelector('.submenu-panel');
        if (!panel) return;
        document.body.appendChild(panel);
        item._panel = panel;

        var hideTimer = null;

        function showPanel() {
            if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
            document.querySelectorAll('.submenu-panel').forEach(function(p) {
                if (p !== panel) p.style.display = 'none';
            });
            var rect = item.getBoundingClientRect();
            panel.style.position = 'fixed';
            panel.style.left = rect.right + 'px';
            panel.style.top = rect.top + 'px';
            panel.style.display = 'block';
            panel.style.zIndex = '99999';
            panel.style.opacity = '1';
            var panelRect = panel.getBoundingClientRect();
            if (panelRect.bottom > window.innerHeight - 10) {
                panel.style.top = (window.innerHeight - panelRect.height - 10) + 'px';
            }
        }

        function hidePanel() {
            hideTimer = setTimeout(function() {
                panel.style.display = 'none';
            }, 100);
        }

        item.addEventListener('mouseenter', showPanel);
        item.addEventListener('mouseleave', hidePanel);
        panel.addEventListener('mouseenter', function() {
            if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
        });
        panel.addEventListener('mouseleave', hidePanel);
    });

    var groupMap = {
        '/contexa/admin/dashboard': 'dashboard',
        '/contexa/admin/policy-center': 'policy',
        '/contexa/admin/access-center': 'access',
        '/contexa/admin/users': 'iam', '/contexa/admin/groups': 'iam', '/contexa/admin/roles': 'iam',
        '/contexa/admin/permissions': 'iam', '/contexa/admin/role-hierarchies': 'iam', '/contexa/admin/password-policy': 'iam',
        '/contexa/admin/security-monitor': 'security',
        '/contexa/admin/zero-trust': 'ai-monitor',
        // The prompt quality assurance group: every screen under its addresses, the second bundle's included.
        '/contexa/admin/prompt-quality': 'prompt-quality', '/contexa/admin/prompt-inspection': 'prompt-quality',
        '/contexa/admin/blacklist': 'security', '/contexa/admin/session-management': 'security', '/contexa/admin/ip-management': 'security',
        '/contexa/admin/enterprise/zerotrust': 'security', '/contexa/admin/enterprise/incidents': 'security',
        '/contexa/admin/enterprise': 'enterprise',
        '/contexa/admin/enterprise/approvals': 'enterprise', '/contexa/admin/enterprise/mcp': 'enterprise',
        '/contexa/admin/enterprise/permits': 'enterprise', '/contexa/admin/enterprise/executions': 'enterprise',
        '/contexa/admin/enterprise/playbooks': 'enterprise', '/contexa/admin/enterprise/verification': 'enterprise',
        '/contexa/admin/enterprise/verification/context': 'enterprise', '/contexa/admin/enterprise/verification/decision': 'enterprise',
        '/contexa/admin/enterprise/metrics': 'enterprise',
        '/contexa/admin/enterprise/integration': 'enterprise',
        '/contexa/admin/saas': 'saas'
    };

    var activeGroup = null;
    var keys = Object.keys(groupMap);
    for (var i = 0; i < keys.length; i++) {
        if (path === keys[i] || path.startsWith(keys[i] + '/')) {
            activeGroup = groupMap[keys[i]];
        }
    }
    if (path === '/contexa/admin/dashboard' || path === '/contexa/admin' || path === '/contexa/admin/') activeGroup = 'dashboard';

    if (activeGroup) {
        var mainLink = document.querySelector('.main-menu-link[data-group="' + activeGroup + '"]');
        if (mainLink) mainLink.classList.add('active');
    }

    // Only the longest address that holds the page lights up: the Zero Trust overview's address starts every
    // console screen's, and the screen's own menu is the one meant.
    var submenuLinks = Array.prototype.slice.call(document.querySelectorAll('.submenu-link'));
    var longest = -1;
    submenuLinks.forEach(function(link) {
        var href = link.getAttribute('href');
        href = href ? withinApp(href) : href;
        if (href && (path === href || path.startsWith(href + '/')) && href.length > longest) {
            longest = href.length;
        }
    });
    submenuLinks.forEach(function(link) {
        var href = link.getAttribute('href');
        href = href ? withinApp(href) : href;
        if (href && href.length === longest && (path === href || path.startsWith(href + '/'))) {
            link.classList.add('active');
        }
    });

    if ('ontouchstart' in window) {
        document.querySelectorAll('.main-menu-item.has-submenu').forEach(function(item) {
            var link = item.querySelector('.main-menu-link');
            if (link) {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    var panel = item._panel;
                    if (!panel) return;
                    var isVisible = panel.style.display === 'block';
                    document.querySelectorAll('.submenu-panel').forEach(function(p) { p.style.display = 'none'; });
                    if (!isVisible) {
                        var rect = item.getBoundingClientRect();
                        panel.style.position = 'fixed';
                        panel.style.left = rect.right + 'px';
                        panel.style.top = rect.top + 'px';
                        panel.style.display = 'block';
                        panel.style.zIndex = '99999';
                        panel.style.opacity = '1';
                    }
                });
            }
        });
    }
});
