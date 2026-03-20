-- ============================================================
-- Contexa AI-Native Zero Trust Security Platform
-- Initial Data (DML)
-- Version: 0.1.0
-- ============================================================
-- Run AFTER ddlScript.sql
-- Password: BCrypt encoded 'admin123' / 'manager123' / 'user123'
-- ============================================================

-- ============================================================
-- 1. Roles
-- ============================================================

INSERT INTO role (role_name, role_desc, is_expression, enabled, created_at, created_by) VALUES
    ('ROLE_ADMIN',   'System administrator with full access',    FALSE, TRUE, CURRENT_TIMESTAMP, 'SYSTEM'),
    ('ROLE_MANAGER', 'Manager with team-level access',           FALSE, TRUE, CURRENT_TIMESTAMP, 'SYSTEM'),
    ('ROLE_USER',    'Standard user with basic access',          FALSE, TRUE, CURRENT_TIMESTAMP, 'SYSTEM'),
    ('ROLE_DEVELOPER', 'Developer with API and resource access', FALSE, TRUE, CURRENT_TIMESTAMP, 'SYSTEM');

-- ============================================================
-- 2. Groups
-- ============================================================

INSERT INTO app_group (group_name, description, enabled, created_at, created_by) VALUES
    ('Administrators', 'System administrators group',           TRUE, CURRENT_TIMESTAMP, 'SYSTEM'),
    ('Managers',       'Team managers group',                   TRUE, CURRENT_TIMESTAMP, 'SYSTEM'),
    ('Users',          'Standard users group',                  TRUE, CURRENT_TIMESTAMP, 'SYSTEM'),
    ('Developers',     'Developers and engineers group',        TRUE, CURRENT_TIMESTAMP, 'SYSTEM');

-- ============================================================
-- 3. Group-Role Assignments
--    Administrators: ROLE_ADMIN + ROLE_MANAGER + ROLE_USER
--    Managers:       ROLE_MANAGER + ROLE_USER
--    Users:          ROLE_USER
--    Developers:     ROLE_DEVELOPER + ROLE_USER
-- ============================================================

INSERT INTO group_roles (group_id, role_id, assigned_at, assigned_by)
SELECT g.group_id, r.role_id, CURRENT_TIMESTAMP, 'SYSTEM'
FROM app_group g, role r
WHERE (g.group_name = 'Administrators' AND r.role_name IN ('ROLE_ADMIN', 'ROLE_MANAGER', 'ROLE_USER'))
   OR (g.group_name = 'Managers'       AND r.role_name IN ('ROLE_MANAGER', 'ROLE_USER'))
   OR (g.group_name = 'Users'          AND r.role_name IN ('ROLE_USER'))
   OR (g.group_name = 'Developers'     AND r.role_name IN ('ROLE_DEVELOPER', 'ROLE_USER'));

-- ============================================================
-- 4. Users
--    Passwords are BCrypt encoded:
--      admin123   -> $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
--      manager123 -> $2a$10$dXJ3SW6G7P50lGmMQgel5uVf3JCDq1w3r4bXaECY5V5Q7Ggk3jYlC
--      user123    -> $2a$10$KkQZkYMGJPk7Xe1JhDcFGeYMM0E.VIiLvSdPqbMjPFHCdGo.ZsSXy
-- ============================================================

INSERT INTO users (username, email, password, name, phone, department, position, enabled, mfa_enabled, created_at) VALUES
    ('admin',       'admin@contexa.io',       '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'System Admin',   '010-0000-0001', 'IT',          'Administrator', TRUE, FALSE, CURRENT_TIMESTAMP),
    ('kim_manager', 'kim.manager@contexa.io', '$2a$10$dXJ3SW6G7P50lGmMQgel5uVf3JCDq1w3r4bXaECY5V5Q7Ggk3jYlC', 'Kim Jihoon',     '010-0000-0002', 'Finance',     'Manager',       TRUE, FALSE, CURRENT_TIMESTAMP),
    ('park_user',   'park.user@contexa.io',   '$2a$10$KkQZkYMGJPk7Xe1JhDcFGeYMM0E.VIiLvSdPqbMjPFHCdGo.ZsSXy', 'Park Minjun',    '010-0000-0003', 'Engineering', 'Developer',     TRUE, FALSE, CURRENT_TIMESTAMP),
    ('dev_lead',    'dev.lead@contexa.io',    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'Lee Soyeon',     '010-0000-0004', 'Engineering', 'Tech Lead',     TRUE, FALSE, CURRENT_TIMESTAMP);

-- ============================================================
-- 5. User-Group Assignments
--    admin       -> Administrators
--    kim_manager -> Managers
--    park_user   -> Users
--    dev_lead    -> Developers
-- ============================================================

INSERT INTO user_groups (user_id, group_id, assigned_at, assigned_by)
SELECT u.id, g.group_id, CURRENT_TIMESTAMP, 'SYSTEM'
FROM users u, app_group g
WHERE (u.username = 'admin'       AND g.group_name = 'Administrators')
   OR (u.username = 'kim_manager' AND g.group_name = 'Managers')
   OR (u.username = 'park_user'   AND g.group_name = 'Users')
   OR (u.username = 'dev_lead'    AND g.group_name = 'Developers');
