-- ============================================================
-- Contexa IAM sample accounts (Q-32): five accounts that share one known password, for a local quick start only.
-- Run only when contexa.iam.seed.accounts.enabled is true (default false); never turn it on for a deployment.
-- Every INSERT is idempotent (ON CONFLICT DO NOTHING), as in db/data.sql, whose roles and groups these rows name.
-- ============================================================

-- ----------------------------------------------------------------
-- USERS — required NOT NULL: account_locked, bridge_managed,
-- credentials_expired, enabled, external_auth_only,
-- failed_login_attempts, mfa_enabled, created_at, name, username, password.
-- ----------------------------------------------------------------
INSERT INTO USERS (id, username, password, name, email, mfa_enabled, enabled, account_locked, bridge_managed, credentials_expired, external_auth_only, failed_login_attempts, created_at) VALUES
    (1, 'admin',     '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '최고관리자', 'admin@gmail.com', TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (2, 'manager',   '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '김팀장',     'manager@gmail.com',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (3, 'developer', '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '박개발',     'developer@gmail.com',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (4, 'user',      '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '이운영',     'user@gmail.com',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (5, 'finance',   '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '최재무',     'finance@gmail.com',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------
-- USER_GROUPS — required NOT NULL: assigned_at, group_id, user_id.
-- ----------------------------------------------------------------
INSERT INTO USER_GROUPS (user_id, group_id, assigned_at) VALUES
    (1, 1, CURRENT_TIMESTAMP),
    (2, 2, CURRENT_TIMESTAMP),
    (3, 2, CURRENT_TIMESTAMP),
    (4, 3, CURRENT_TIMESTAMP),
    (5, 4, CURRENT_TIMESTAMP)
ON CONFLICT (group_id, user_id) DO NOTHING;
