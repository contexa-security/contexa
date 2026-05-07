-- Admin Menu Initial Data
-- Idempotent on data_page (unique business key consumed by AdminMenuService.findByDataPage).
-- WHERE NOT EXISTS prevents duplicate rows when AdminMenuService.ensureMenu() has previously
-- inserted rows under different surrogate IDs.
-- Schema source-of-truth: contexa_tables.sql (operational DB dump 2026-05-07).

-- ----------------------------------------------------------------
-- Top-level groups (parent_id = NULL)
-- ----------------------------------------------------------------
INSERT INTO admin_menu (name, url, icon, parent_id, menu_order, enabled, menu_type, data_page)
SELECT v.name, v.url, v.icon, v.parent_id, v.menu_order, v.enabled, v.menu_type, v.data_page
  FROM (VALUES
    ('menu.dashboard',      '/admin/dashboard', '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"/></svg>', NULL::BIGINT, 1, TRUE, 'CORE',       'dashboard'),
    ('menu.nav.policy',     NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>',                                                                                                                                                                                                                                                                       NULL::BIGINT, 2, TRUE, 'CORE',       'policy'),
    ('menu.nav.access',     NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>',                                                                                                                                                                                                                                                                              NULL::BIGINT, 3, TRUE, 'CORE',       'access'),
    ('menu.nav.iam',        NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"/></svg>',                                                                                                  NULL::BIGINT, 4, TRUE, 'CORE',       'iam'),
    ('menu.nav.security',   NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>',                                                                                                                                                                              NULL::BIGINT, 5, TRUE, 'CORE',       'security'),
    ('menu.nav.enterprise', NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"/></svg>',                                                                                                                                                                                                                                                                                              NULL::BIGINT, 6, TRUE, 'ENTERPRISE', 'enterprise'),
    ('menu.nav.saas',       NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z"/></svg>',                                                                                                                                                                                                                                                                                                                                                  NULL::BIGINT, 7, TRUE, 'SAAS',       'saas')
  ) AS v(name, url, icon, parent_id, menu_order, enabled, menu_type, data_page)
 WHERE NOT EXISTS (SELECT 1 FROM admin_menu m WHERE m.data_page = v.data_page);

-- ----------------------------------------------------------------
-- Submenu items (parent_id resolved by SELECT for stability under regenerated IDs)
-- ----------------------------------------------------------------
INSERT INTO admin_menu (name, url, icon, parent_id, menu_order, enabled, menu_type, data_page)
SELECT v.name, v.url, '', p.id, v.menu_order, TRUE, v.menu_type, v.data_page
  FROM (VALUES
    ('menu.policy.center',          '/admin/policy-center',         'policy',     1, 'CORE',       'policy-center'),
    ('menu.access.center',          '/admin/access-center',         'access',     1, 'CORE',       'access-center'),
    ('menu.iam.users',              '/admin/users',                 'iam',        1, 'CORE',       'users'),
    ('menu.iam.groups',             '/admin/groups',                'iam',        2, 'CORE',       'groups'),
    ('menu.iam.roles',              '/admin/roles',                 'iam',        3, 'CORE',       'roles'),
    ('menu.iam.permissions',        '/admin/permissions',           'iam',        4, 'CORE',       'permissions'),
    ('menu.iam.role.hierarchies',   '/admin/role-hierarchies',      'iam',        5, 'CORE',       'role-hierarchies'),
    ('menu.iam.password.policy',    '/admin/password-policy',       'iam',        6, 'CORE',       'password-policy'),
    ('menu.iam.system.settings',    '/admin/system-settings',       'iam',        7, 'CORE',       'system-settings'),
    ('menu.iam.menu.management',    '/admin/menu-management',       'iam',        8, 'CORE',       'menu-management'),
    ('menu.zerotrust.monitor',      '/admin/security-monitor',      'security',   1, 'CORE',       'security-monitor'),
    ('menu.zerotrust.blacklist',    '/admin/blacklist',             'security',   2, 'CORE',       'blacklist'),
    ('menu.security.sessions',      '/admin/session-management',    'security',   3, 'CORE',       'session-management'),
    ('menu.security.ip',            '/admin/ip-management',         'security',   4, 'CORE',       'ip-management'),
    ('menu.enterprise.zerotrust',   '/admin/enterprise/zerotrust',  'security',   5, 'ENTERPRISE', 'enterprise-zerotrust'),
    ('menu.enterprise.incidents',   '/admin/enterprise/incidents',  'security',   6, 'ENTERPRISE', 'enterprise-incidents'),
    ('menu.enterprise.home',        '/admin/enterprise',            'enterprise', 1, 'ENTERPRISE', 'enterprise-home'),
    ('menu.enterprise.approvals',   '/admin/enterprise/approvals',  'enterprise', 2, 'ENTERPRISE', 'enterprise-approvals'),
    ('menu.enterprise.mcp',         '/admin/enterprise/mcp',        'enterprise', 3, 'ENTERPRISE', 'enterprise-mcp'),
    ('menu.enterprise.permits',     '/admin/enterprise/permits',    'enterprise', 4, 'ENTERPRISE', 'enterprise-permits'),
    ('menu.enterprise.executions',  '/admin/enterprise/executions', 'enterprise', 5, 'ENTERPRISE', 'enterprise-executions'),
    ('menu.enterprise.playbooks',   '/admin/enterprise/playbooks',  'enterprise', 6, 'ENTERPRISE', 'enterprise-playbooks'),
    ('menu.enterprise.metrics',     '/admin/enterprise/metrics',    'enterprise', 7, 'ENTERPRISE', 'enterprise-metrics'),
    ('menu.enterprise.integration', '/admin/enterprise/integration','enterprise', 8, 'ENTERPRISE', 'enterprise-integration'),
    ('menu.saas.tenants',           '/admin/saas/tenants',          'saas',       1, 'SAAS',       'saas-platform-tenants'),
    ('menu.saas.billing',           '/admin/saas/billing',          'saas',       2, 'SAAS',       'saas-platform-billing'),
    ('menu.saas.dedicated',         '/admin/saas/dedicated',        'saas',       3, 'SAAS',       'saas-platform-dedicated'),
    ('menu.saas.release.governance','/admin/saas/release-governance','saas',      4, 'SAAS',       'saas-release-governance'),
    ('menu.saas.tenant.workspace',  '/admin/saas/tenant/workspace', 'saas',       5, 'SAAS',       'saas-tenant-workspace'),
    ('menu.saas.learning',          '/admin/saas/learning/overview','saas',       6, 'SAAS',       'saas-learning-overview')
  ) AS v(name, url, parent_data_page, menu_order, menu_type, data_page)
  JOIN admin_menu p ON p.data_page = v.parent_data_page AND p.parent_id IS NULL
 WHERE NOT EXISTS (SELECT 1 FROM admin_menu m WHERE m.data_page = v.data_page);
