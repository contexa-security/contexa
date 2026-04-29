document.addEventListener('DOMContentLoaded', function() {
    var path = window.location.pathname;

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
        '/admin/dashboard': 'dashboard',
        '/admin/policy-center': 'policy',
        '/admin/access-center': 'access',
        '/admin/users': 'iam', '/admin/groups': 'iam', '/admin/roles': 'iam',
        '/admin/permissions': 'iam', '/admin/role-hierarchies': 'iam', '/admin/password-policy': 'iam',
        '/admin/security-monitor': 'security', '/admin/blacklist': 'security', '/admin/session-management': 'security', '/admin/ip-management': 'security',
        '/admin/enterprise/zerotrust': 'security', '/admin/enterprise/incidents': 'security',
        '/admin/enterprise': 'enterprise',
        '/admin/enterprise/approvals': 'enterprise', '/admin/enterprise/mcp': 'enterprise',
        '/admin/enterprise/permits': 'enterprise', '/admin/enterprise/executions': 'enterprise',
        '/admin/enterprise/playbooks': 'enterprise', '/admin/enterprise/verification': 'enterprise',
        '/admin/enterprise/verification/context': 'enterprise', '/admin/enterprise/verification/decision': 'enterprise',
        '/admin/enterprise/metrics': 'enterprise',
        '/admin/enterprise/integration': 'enterprise',
        '/admin/saas': 'saas'
    };

    var activeGroup = null;
    var keys = Object.keys(groupMap);
    for (var i = 0; i < keys.length; i++) {
        if (path === keys[i] || path.startsWith(keys[i] + '/')) {
            activeGroup = groupMap[keys[i]];
        }
    }
    if (path === '/admin/dashboard' || path === '/admin' || path === '/admin/') activeGroup = 'dashboard';

    if (activeGroup) {
        var mainLink = document.querySelector('.main-menu-link[data-group="' + activeGroup + '"]');
        if (mainLink) mainLink.classList.add('active');
    }

    document.querySelectorAll('.submenu-link').forEach(function(link) {
        var href = link.getAttribute('href');
        if (href && (path === href || path.startsWith(href + '/'))) {
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
