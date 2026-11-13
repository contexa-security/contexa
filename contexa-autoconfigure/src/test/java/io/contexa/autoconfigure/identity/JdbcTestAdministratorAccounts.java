/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.identity;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The administrator seed's accounts on the small schema of IamSeedAdministratorTest, which has no JPA context: the same
 * rows the application's {@link JpaAdministratorAccounts} writes through the repositories.
 */
final class JdbcTestAdministratorAccounts implements AdministratorAccounts {

    private final JdbcTemplate jdbc;

    JdbcTestAdministratorAccounts(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public boolean exists(String username, String email) {
        Integer count = jdbc.queryForObject(
                "select count(*) from ctxa_users where username = ? or lower(email) = lower(?)", Integer.class,
                username, email);
        return count != null && count > 0;
    }

    @Override
    public long create(String username, String email, String encodedPassword, String name) {
        jdbc.update("insert into ctxa_users (username, email, password, name, enabled, account_locked, credentials_expired, "
                        + "failed_login_attempts, mfa_enabled, bridge_managed, external_auth_only, created_at) "
                        + "values (?, ?, ?, ?, true, false, false, 0, true, false, false, current_timestamp)",
                username, email, encodedPassword, name);
        return jdbc.queryForObject("select id from ctxa_users where username = ?", Long.class, username);
    }

    @Override
    public boolean groupExists(long groupId) {
        Integer count = jdbc.queryForObject("select count(*) from ctxa_app_group where group_id = ?", Integer.class,
                groupId);
        return count != null && count > 0;
    }

    @Override
    public void join(long userId, long groupId) {
        jdbc.update("insert into ctxa_user_groups (user_id, group_id, assigned_at) values (?, ?, current_timestamp)",
                userId, groupId);
    }
}
