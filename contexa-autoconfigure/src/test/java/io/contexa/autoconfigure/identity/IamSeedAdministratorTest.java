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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

/** One administrator from contexa.iam.seed.admin.*, against the columns db/schema.sql gives users. */
class IamSeedAdministratorTest {

    private DataSource dataSource;
    private JdbcTemplate jdbc;

    @BeforeEach
    void createTables() {
        dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:seed-admin-" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table ctxa_users (id bigserial primary key, username varchar(100) not null unique, "
                + "email varchar(255) not null unique, password varchar(255) not null, name varchar(100) not null, "
                + "enabled boolean default true not null, account_locked boolean default false not null, "
                + "credentials_expired boolean default false not null, failed_login_attempts integer default 0 not null, "
                + "mfa_enabled boolean default false not null, created_at timestamp(6) default current_timestamp not null, "
                + "bridge_managed boolean default false not null, external_auth_only boolean default false not null)");
        jdbc.execute("create table ctxa_app_group (group_id bigint primary key, group_name varchar(100) not null)");
        jdbc.execute("create table ctxa_user_groups (user_id bigint not null references ctxa_users on delete cascade, "
                + "group_id bigint not null references ctxa_app_group on delete cascade, "
                + "assigned_at timestamp(6) default current_timestamp not null, primary key (user_id, group_id))");
        jdbc.update("insert into ctxa_app_group (group_id, group_name) values (1, 'system administrators')");
    }

    @Test
    @DisplayName("Administrator seed: without contexa.iam.seed.admin.password nothing is created")
    void nothingWithoutPassword() {
        assertThat(IamSeedDataAutoConfiguration.seedAdministrator(dataSource, new MockEnvironment()))
                .isEqualTo(IamSeedDataAutoConfiguration.AdministratorSeed.NOT_REQUESTED);
        assertThat(IamSeedDataAutoConfiguration.seedAdministrator(dataSource, new MockEnvironment()
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_PASSWORD_PROPERTY, "  ")))
                .isEqualTo(IamSeedDataAutoConfiguration.AdministratorSeed.NOT_REQUESTED);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_users", Integer.class)).isZero();
    }

    @Test
    @DisplayName("Administrator seed: the administrator gets the encoded password, two-step sign-in and the administrators group")
    void createsTheAdministrator() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_PASSWORD_PROPERTY, "Kp7mVx2qRt9wZb4n");

        assertThat(IamSeedDataAutoConfiguration.seedAdministrator(dataSource, environment))
                .isEqualTo(IamSeedDataAutoConfiguration.AdministratorSeed.CREATED);

        Map<String, Object> user = jdbc.queryForMap("select * from ctxa_users");
        assertThat(user.get("USERNAME")).isEqualTo("admin");
        assertThat(user.get("EMAIL")).isEqualTo("admin@localhost");
        assertThat(user.get("ENABLED")).isEqualTo(true);
        assertThat(user.get("MFA_ENABLED")).isEqualTo(true);
        String stored = (String) user.get("PASSWORD");
        assertThat(stored).startsWith("{bcrypt}").doesNotContain("Kp7mVx2qRt9wZb4n");
        assertThat(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches("Kp7mVx2qRt9wZb4n", stored)).isTrue();
        assertThat(jdbc.queryForObject("select group_id from ctxa_user_groups where user_id = ?", Long.class, user.get("ID")))
                .isEqualTo(IamSeedDataAutoConfiguration.ADMIN_GROUP_ID);
    }

    @Test
    @DisplayName("Administrator seed: a later start never changes an existing administrator, so a password changed in the console stays")
    void leavesAnExistingAdministratorAlone() {
        IamSeedDataAutoConfiguration.seedAdministrator(dataSource, new MockEnvironment()
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_PASSWORD_PROPERTY, "first-password"));
        String stored = jdbc.queryForObject("select password from ctxa_users", String.class);

        assertThat(IamSeedDataAutoConfiguration.seedAdministrator(dataSource, new MockEnvironment()
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_PASSWORD_PROPERTY, "second-password")))
                .isEqualTo(IamSeedDataAutoConfiguration.AdministratorSeed.ALREADY_PRESENT);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_users", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select password from ctxa_users", String.class)).isEqualTo(stored);
    }

    @Test
    @DisplayName("Administrator seed: username and e-mail can be chosen; an e-mail another user has means nothing is created")
    void chosenNamesAndCollisions() {
        jdbc.update("insert into ctxa_users (username, email, password, name) values ('kim', 'ops@example.com', 'x', 'Kim')");

        assertThat(IamSeedDataAutoConfiguration.seedAdministrator(dataSource, new MockEnvironment()
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_PASSWORD_PROPERTY, "secret")
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_USERNAME_PROPERTY, "root")
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_EMAIL_PROPERTY, "ops@example.com")))
                .isEqualTo(IamSeedDataAutoConfiguration.AdministratorSeed.ALREADY_PRESENT);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_users", Integer.class)).isEqualTo(1);

        assertThat(IamSeedDataAutoConfiguration.seedAdministrator(dataSource, new MockEnvironment()
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_PASSWORD_PROPERTY, "secret")
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_USERNAME_PROPERTY, "root")
                .withProperty(IamSeedDataAutoConfiguration.ADMIN_EMAIL_PROPERTY, "root@example.com")))
                .isEqualTo(IamSeedDataAutoConfiguration.AdministratorSeed.CREATED);
        assertThat(jdbc.queryForObject("select email from ctxa_users where username = 'root'", String.class))
                .isEqualTo("root@example.com");
    }
}
