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
        '/contexa/admin/dashboard': 'dashboard',
        '/contexa/admin/policy-center': 'policy',
        '/contexa/admin/access-center': 'access',
        '/contexa/admin/users': 'iam', '/contexa/admin/groups': 'iam', '/contexa/admin/roles': 'iam',
        '/contexa/admin/permissions': 'iam', '/contexa/admin/role-hierarchies': 'iam', '/contexa/admin/password-policy': 'iam',
        '/contexa/admin/security-monitor': 'security', '/contexa/admin/blacklist': 'security', '/contexa/admin/session-management': 'security', '/contexa/admin/ip-management': 'security',
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
