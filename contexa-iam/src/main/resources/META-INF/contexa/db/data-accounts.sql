-- ============================================================
-- Contexa IAM sample accounts: five accounts that share the password 1111, so that a first start can be signed in to.
-- Added only to a database without user accounts, unless contexa.iam.seed.accounts.enabled is false.
-- Every INSERT is idempotent (ON CONFLICT DO NOTHING), as in META-INF/contexa/db/data.sql, whose roles and groups these rows name.
-- ============================================================

-- ----------------------------------------------------------------
-- USERS — required NOT NULL: account_locked, bridge_managed,
-- credentials_expired, enabled, external_auth_only,
-- failed_login_attempts, mfa_enabled, created_at, name, username, password.
-- ----------------------------------------------------------------
INSERT INTO CTXA_USERS (id, username, password, name, email, mfa_enabled, enabled, account_locked, bridge_managed, credentials_expired, external_auth_only, failed_login_attempts, created_at) VALUES
    (1, 'admin',     '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '최고관리자', 'admin@localhost', TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (2, 'manager',   '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '김팀장',     'manager@localhost',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (3, 'developer', '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '박개발',     'developer@localhost',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (4, 'user',      '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '이운영',     'user@localhost',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (5, 'finance',   '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '최재무',     'finance@localhost',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------
-- USER_GROUPS — required NOT NULL: assigned_at, group_id, user_id.
-- ----------------------------------------------------------------
INSERT INTO CTXA_USER_GROUPS (user_id, group_id, assigned_at) VALUES
    (1, 1, CURRENT_TIMESTAMP),
    (2, 2, CURRENT_TIMESTAMP),
    (3, 2, CURRENT_TIMESTAMP),
    (4, 3, CURRENT_TIMESTAMP),
    (5, 4, CURRENT_TIMESTAMP)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- ----------------------------------------------------------------
-- The sequence follows the ids set above (as META-INF/contexa/db/data.sql does for its rows), so that the next user created,
-- such as the bridge's mirror of a signed-in user, takes a free id.
-- ----------------------------------------------------------------
SELECT setval('ctxa_users_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM ctxa_users), 0), 1), COALESCE((SELECT MAX(id) FROM ctxa_users), 0) > 0)
WHERE to_regclass('ctxa_users_id_seq') IS NOT NULL;
