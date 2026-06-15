-- Admin Menu Initial Data
-- Source seed: current admin_menu data from the operational DB on 2026-05-07.
-- data_page is the menu business key used by AdminMenuService.

-- ----------------------------------------------------------------
-- Repair duplicate business keys created by earlier seed versions.
-- Keep the lowest id, move children and roles to it, then delete duplicates.
-- ----------------------------------------------------------------
WITH duplicate_menu AS (
    SELECT id, MIN(id) OVER (PARTITION BY data_page) AS keep_id
      FROM admin_menu
     WHERE data_page IS NOT NULL
)
INSERT INTO admin_menu_role (menu_id, role_name)
SELECT DISTINCT d.keep_id, r.role_name
  FROM duplicate_menu d
  JOIN admin_menu_role r ON r.menu_id = d.id
 WHERE d.id <> d.keep_id
ON CONFLICT (menu_id, role_name) DO NOTHING;

WITH duplicate_menu AS (
    SELECT id, MIN(id) OVER (PARTITION BY data_page) AS keep_id
      FROM admin_menu
     WHERE data_page IS NOT NULL
)
UPDATE admin_menu child
   SET parent_id = d.keep_id
  FROM duplicate_menu d
 WHERE child.parent_id = d.id
   AND d.id <> d.keep_id;

WITH duplicate_menu AS (
    SELECT id, MIN(id) OVER (PARTITION BY data_page) AS keep_id
      FROM admin_menu
     WHERE data_page IS NOT NULL
)
DELETE FROM admin_menu_role r
 USING duplicate_menu d
 WHERE r.menu_id = d.id
   AND d.id <> d.keep_id;

WITH duplicate_menu AS (
    SELECT id, MIN(id) OVER (PARTITION BY data_page) AS keep_id
      FROM admin_menu
     WHERE data_page IS NOT NULL
)
DELETE FROM admin_menu m
 USING duplicate_menu d
 WHERE m.id = d.id
   AND d.id <> d.keep_id;

CREATE UNIQUE INDEX IF NOT EXISTS ux_admin_menu_data_page
    ON admin_menu (data_page)
 WHERE data_page IS NOT NULL;

-- ----------------------------------------------------------------
-- Top-level groups (parent_id = NULL)
-- ----------------------------------------------------------------
WITH seed(name, url, icon, parent_id, menu_order, enabled, menu_type, data_page) AS (
    VALUES
    ('menu.dashboard',      '/contexa/admin/dashboard', '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"/></svg>', NULL::BIGINT, 1, TRUE, 'CORE',       'dashboard'),
    ('menu.nav.policy',     NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>',                                                                                                                                                                                                                                                                       NULL::BIGINT, 2, TRUE, 'CORE',       'policy'),
    ('menu.nav.access',     NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>',                                                                                                                                                                                                                                                                              NULL::BIGINT, 3, TRUE, 'CORE',       'access'),
    ('menu.nav.iam',        NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"/></svg>',                                                                                                  NULL::BIGINT, 4, TRUE, 'CORE',       'iam'),
    ('menu.nav.security',   NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>',                                                                                                                                                                              NULL::BIGINT, 5, TRUE, 'CORE',       'security'),
    ('menu.nav.pqa',        NULL,               '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="24" height="24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 3h6m2.25 5.25h-10.5A2.25 2.25 0 014.5 18V6A2.25 2.25 0 016.75 3.75h6.879c.597 0 1.169.237 1.591.659l3.621 3.621c.422.422.659.994.659 1.591V18a2.25 2.25 0 01-2.25 2.25z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.5 3.75V8.25c0 .621.504 1.125 1.125 1.125H19.5"/></svg>',                                                                                                                                                                          NULL::BIGINT, 6, TRUE, 'CORE',       'prompt-quality')
),
updated AS (
    UPDATE admin_menu m
       SET name = s.name,
           url = s.url,
           icon = s.icon,
           parent_id = s.parent_id,
           menu_order = s.menu_order,
           enabled = s.enabled,
           menu_type = s.menu_type
      FROM seed s
     WHERE m.data_page = s.data_page
 RETURNING m.data_page
)
INSERT INTO admin_menu (name, url, icon, parent_id, menu_order, enabled, menu_type, data_page)
SELECT s.name, s.url, s.icon, s.parent_id, s.menu_order, s.enabled, s.menu_type, s.data_page
  FROM seed s
 WHERE NOT EXISTS (SELECT 1 FROM updated u WHERE u.data_page = s.data_page)
   AND NOT EXISTS (SELECT 1 FROM admin_menu m WHERE m.data_page = s.data_page);

-- ----------------------------------------------------------------
-- Submenu items (parent_id resolved by data_page for stability under regenerated IDs)
-- ----------------------------------------------------------------
WITH seed(name, url, icon, parent_data_page, menu_order, enabled, menu_type, data_page) AS (
    VALUES
    ('menu.policy.center',           '/contexa/admin/policy-center',          '',                'policy',     1,  TRUE, 'CORE',       'policy-center'),
    ('menu.access.center',           '/contexa/admin/access-center',          '',                'access',     1,  TRUE, 'CORE',       'access-center'),
    ('menu.iam.users',               '/contexa/admin/users',                  '',                'iam',        1,  TRUE, 'CORE',       'users'),
    ('menu.iam.groups',              '/contexa/admin/groups',                 '',                'iam',        2,  TRUE, 'CORE',       'groups'),
    ('menu.iam.roles',               '/contexa/admin/roles',                  '',                'iam',        3,  TRUE, 'CORE',       'roles'),
    ('menu.iam.permissions',         '/contexa/admin/permissions',            '',                'iam',        4,  TRUE, 'CORE',       'permissions'),
    ('menu.iam.role.hierarchies',    '/contexa/admin/role-hierarchies',       '',                'iam',        5,  TRUE, 'CORE',       'role-hierarchies'),
    ('menu.iam.password.policy',     '/contexa/admin/password-policy',        '',                'iam',        6,  TRUE, 'CORE',       'password-policy'),
    ('menu.iam.system.settings',     '/contexa/admin/system-settings',        '',                'iam',        7,  TRUE, 'CORE',       'system-settings'),
    ('menu.iam.menu.management',     '/contexa/admin/menu-management',        '',                'iam',        8,  TRUE, 'CORE',       'menu-management'),
    ('menu.zerotrust.monitor',       '/contexa/admin/security-monitor',       '',                'security',   1,  TRUE, 'CORE',       'security-monitor'),
    ('menu.zerotrust.blacklist',     '/contexa/admin/blacklist',              '',                'security',   2,  TRUE, 'CORE',       'blacklist'),
    ('menu.security.sessions',       '/contexa/admin/session-management',     '',                'security',   3,  TRUE, 'CORE',       'session-management'),
    ('menu.security.ip',             '/contexa/admin/ip-management',          '',                'security',   4,  TRUE, 'CORE',       'ip-management'),
    ('menu.pqa.resources',           '/contexa/admin/prompt-quality/resources', '',              'prompt-quality', 1, TRUE, 'CORE',       'prompt-quality-resources'),
    ('menu.pqa.runtimeEvidence',     '/contexa/admin/prompt-quality/runtime-evidence', '',       'prompt-quality', 2, TRUE, 'CORE',       'prompt-quality-runtime-evidence'),
    ('menu.pqa.official',            '/contexa/admin/prompt-quality/verification/readiness', '',  'prompt-quality', 3, TRUE, 'CORE',       'prompt-quality-official')
),
resolved AS (
    SELECT s.name, s.url, s.icon, p.id AS parent_id, s.menu_order, s.enabled, s.menu_type, s.data_page
      FROM seed s
      JOIN admin_menu p ON p.data_page = s.parent_data_page AND p.parent_id IS NULL
),
updated AS (
    UPDATE admin_menu m
       SET name = r.name,
           url = r.url,
           icon = r.icon,
           parent_id = r.parent_id,
           menu_order = r.menu_order,
           enabled = r.enabled,
           menu_type = r.menu_type
      FROM resolved r
     WHERE m.data_page = r.data_page
 RETURNING m.data_page
)
INSERT INTO admin_menu (name, url, icon, parent_id, menu_order, enabled, menu_type, data_page)
SELECT r.name, r.url, r.icon, r.parent_id, r.menu_order, r.enabled, r.menu_type, r.data_page
  FROM resolved r
 WHERE NOT EXISTS (SELECT 1 FROM updated u WHERE u.data_page = r.data_page)
   AND NOT EXISTS (SELECT 1 FROM admin_menu m WHERE m.data_page = r.data_page);

-- ----------------------------------------------------------------
-- Sequence sync.
-- Menu rows are seeded without fixed ids, and older/manual data may have
-- advanced ids independently. Keep future UI-created rows from reusing ids.
-- Use plain statements because Spring SQL initialization splits this file on
-- semicolons and cannot safely execute procedural blocks.
-- ----------------------------------------------------------------
SELECT setval('admin_menu_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM admin_menu), 0), 1), COALESCE((SELECT MAX(id) FROM admin_menu), 0) > 0)
WHERE to_regclass('admin_menu_id_seq') IS NOT NULL;

SELECT setval('admin_menu_role_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM admin_menu_role), 0), 1), COALESCE((SELECT MAX(id) FROM admin_menu_role), 0) > 0)
WHERE to_regclass('admin_menu_role_id_seq') IS NOT NULL;
