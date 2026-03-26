document.addEventListener('DOMContentLoaded', function() {
    var path = window.location.pathname;

    // Map URL paths to groups
    var groupMap = {
        '/admin/dashboard': 'dashboard',
        '/admin/policy-center': 'policy',
        '/admin/access-center': 'access',
        '/admin/users': 'iam', '/admin/groups': 'iam', '/admin/roles': 'iam',
        '/admin/permissions': 'iam', '/admin/role-hierarchies': 'iam', '/admin/password-policy': 'iam',
        '/admin/security-monitor': 'security', '/admin/blacklist': 'security',
        '/admin/enterprise/zerotrust': 'security', '/admin/enterprise/incidents': 'security',
        '/admin/enterprise': 'enterprise',
        '/admin/enterprise/approvals': 'enterprise', '/admin/enterprise/mcp': 'enterprise',
        '/admin/enterprise/permits': 'enterprise', '/admin/enterprise/executions': 'enterprise',
        '/admin/enterprise/playbooks': 'enterprise', '/admin/enterprise/metrics': 'enterprise',
        '/admin/enterprise/integration': 'enterprise',
        '/admin/saas': 'saas'
    };

    // Find active group by matching path prefix
    var activeGroup = null;
    var keys = Object.keys(groupMap);
    for (var i = 0; i < keys.length; i++) {
        if (path === keys[i] || path.startsWith(keys[i] + '/')) {
            activeGroup = groupMap[keys[i]];
            break;
        }
    }

    // Highlight active main menu item
    if (activeGroup) {
        var mainLink = document.querySelector('.main-menu-link[data-group="' + activeGroup + '"]');
        if (mainLink) mainLink.classList.add('active');
    }

    // Highlight active submenu link
    document.querySelectorAll('.submenu-link').forEach(function(link) {
        var href = link.getAttribute('href') || link.getAttribute('th:href');
        if (href && (path === href || path.startsWith(href + '/'))) {
            link.classList.add('active');
        }
    });

    // Mobile touch support
    if ('ontouchstart' in window) {
        document.querySelectorAll('.main-menu-item.has-submenu').forEach(function(item) {
            item.addEventListener('click', function(e) {
                if (!e.target.closest('.submenu-link')) {
                    e.preventDefault();
                    // Close other open submenus
                    document.querySelectorAll('.main-menu-item.submenu-open').forEach(function(other) {
                        if (other !== item) other.classList.remove('submenu-open');
                    });
                    item.classList.toggle('submenu-open');
                }
            });
        });
    }

    // Submenu overflow prevention
    document.querySelectorAll('.main-menu-item.has-submenu').forEach(function(item) {
        item.addEventListener('mouseenter', function() {
            var panel = this.querySelector('.submenu-panel');
            if (!panel) return;
            panel.style.top = '';
            panel.style.bottom = '';
            var rect = panel.getBoundingClientRect();
            if (rect.bottom > window.innerHeight - 10) {
                panel.style.top = 'auto';
                panel.style.bottom = '0';
            }
        });
    });
});
