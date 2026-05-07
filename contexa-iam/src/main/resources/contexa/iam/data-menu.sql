-- Admin Menu Initial Data
-- Idempotent: ON CONFLICT (id) DO NOTHING ensures safe re-runs at boot.
-- Groups (parent_id = null)
INSERT INTO admin_menu (id, name, url, icon, parent_id, menu_order, enabled, menu_type, data_page) VALUES
(1, 'menu.dashboard', '/admin/dashboard', '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"/></svg>', NULL, 1, true, 'CORE', 'dashboard'),
(2, 'menu.nav.policy', NULL, '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>', NULL, 2, true, 'CORE', 'policy'),
(3, 'menu.nav.access', NULL, '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>', NULL, 3, true, 'CORE', 'access'),
(4, 'menu.nav.iam', NULL, '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"/></svg>', NULL, 4, true, 'CORE', 'iam'),
(5, 'menu.nav.security', NULL, '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>', NULL, 5, true, 'CORE', 'security'),
(6, 'menu.nav.enterprise', NULL, '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"/></svg>', NULL, 6, true, 'ENTERPRISE', 'enterprise'),
(7, 'menu.nav.saas', NULL, '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z"/></svg>', NULL, 7, true, 'SAAS', 'saas')
ON CONFLICT (id) DO NOTHING;

-- Submenu items
INSERT INTO admin_menu (id, name, url, icon, parent_id, menu_order, enabled, menu_type, data_page) VALUES
(10, 'menu.policy.center', '/admin/policy-center', '', 2, 1, true, 'CORE', 'policy-center'),
(11, 'menu.access.center', '/admin/access-center', '', 3, 1, true, 'CORE', 'access-center'),
(20, 'menu.iam.users', '/admin/users', '', 4, 1, true, 'CORE', 'users'),
(21, 'menu.iam.groups', '/admin/groups', '', 4, 2, true, 'CORE', 'groups'),
(22, 'menu.iam.roles', '/admin/roles', '', 4, 3, true, 'CORE', 'roles'),
(23, 'menu.iam.permissions', '/admin/permissions', '', 4, 4, true, 'CORE', 'permissions'),
(24, 'menu.iam.role.hierarchies', '/admin/role-hierarchies', '', 4, 5, true, 'CORE', 'role-hierarchies'),
(25, 'menu.iam.password.policy', '/admin/password-policy', '', 4, 6, true, 'CORE', 'password-policy'),
(26, 'menu.iam.system.settings', '/admin/system-settings', '', 4, 7, true, 'CORE', 'system-settings'),
(27, 'menu.iam.menu.management', '/admin/menu-management', '', 4, 8, true, 'CORE', 'menu-management'),
(30, 'menu.zerotrust.monitor', '/admin/security-monitor', '', 5, 1, true, 'CORE', 'security-monitor'),
(31, 'menu.zerotrust.blacklist', '/admin/blacklist', '', 5, 2, true, 'CORE', 'blacklist'),
(32, 'menu.security.sessions', '/admin/session-management', '', 5, 3, true, 'CORE', 'session-management'),
(33, 'menu.security.ip', '/admin/ip-management', '', 5, 4, true, 'CORE', 'ip-management'),
(34, 'menu.enterprise.zerotrust', '/admin/enterprise/zerotrust', '', 5, 5, true, 'ENTERPRISE', 'enterprise-zerotrust'),
(35, 'menu.enterprise.incidents', '/admin/enterprise/incidents', '', 5, 6, true, 'ENTERPRISE', 'enterprise-incidents'),
(40, 'menu.enterprise.home', '/admin/enterprise', '', 6, 1, true, 'ENTERPRISE', 'enterprise-home'),
(41, 'menu.enterprise.approvals', '/admin/enterprise/approvals', '', 6, 2, true, 'ENTERPRISE', 'enterprise-approvals'),
(42, 'menu.enterprise.mcp', '/admin/enterprise/mcp', '', 6, 3, true, 'ENTERPRISE', 'enterprise-mcp'),
(43, 'menu.enterprise.permits', '/admin/enterprise/permits', '', 6, 4, true, 'ENTERPRISE', 'enterprise-permits'),
(44, 'menu.enterprise.executions', '/admin/enterprise/executions', '', 6, 5, true, 'ENTERPRISE', 'enterprise-executions'),
(45, 'menu.enterprise.playbooks', '/admin/enterprise/playbooks', '', 6, 6, true, 'ENTERPRISE', 'enterprise-playbooks'),
(46, 'menu.enterprise.metrics', '/admin/enterprise/metrics', '', 6, 7, true, 'ENTERPRISE', 'enterprise-metrics'),
(47, 'menu.enterprise.integration', '/admin/enterprise/integration', '', 6, 8, true, 'ENTERPRISE', 'enterprise-integration'),
(50, 'menu.saas.tenants', '/admin/saas/tenants', '', 7, 1, true, 'SAAS', 'saas-platform-tenants'),
(51, 'menu.saas.billing', '/admin/saas/billing', '', 7, 2, true, 'SAAS', 'saas-platform-billing'),
(52, 'menu.saas.dedicated', '/admin/saas/dedicated', '', 7, 3, true, 'SAAS', 'saas-platform-dedicated'),
(53, 'menu.saas.release.governance', '/admin/saas/release-governance', '', 7, 4, true, 'SAAS', 'saas-release-governance'),
(54, 'menu.saas.tenant.workspace', '/admin/saas/tenant/workspace', '', 7, 5, true, 'SAAS', 'saas-tenant-workspace'),
(55, 'menu.saas.learning', '/admin/saas/learning/overview', '', 7, 6, true, 'SAAS', 'saas-learning-overview')
ON CONFLICT (id) DO NOTHING;
