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

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * The seed SQL is UTF-8 and holds Korean names. Java 17 reads files with the operating system's charset
 * (MS949 on Korean Windows, ASCII under a POSIX locale), so the seed has to be read as UTF-8 explicitly.
 */
class IamSeedEncodingTest {

    @Test
    @DisplayName("The seed scripts are read as UTF-8 whatever the JVM's default charset is")
    void seedScriptsAreReadAsUtf8() {
        ResourceDatabasePopulator populator =
                IamSeedDataAutoConfiguration.seedPopulator(new ByteArrayResource(new byte[0]));
        assertThat(ReflectionTestUtils.getField(populator, "sqlScriptEncoding"))
                .isEqualTo(StandardCharsets.UTF_8.name());
    }

    @Test
    @DisplayName("Korean names in a seed script arrive in the database unchanged")
    void koreanSeedRoundTrip() {
        DataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:seed-encoding-" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table app_group (group_id bigint primary key, group_name varchar(100) not null unique)");
        byte[] script = "INSERT INTO app_group (group_id, group_name) VALUES (1, '시스템관리자'), (2, '개발본부');"
                .getBytes(StandardCharsets.UTF_8);

        IamSeedDataAutoConfiguration.seedPopulator(new ByteArrayResource(script)).execute(dataSource);

        assertThat(jdbc.queryForList("select group_name from app_group order by group_id", String.class))
                .containsExactly("시스템관리자", "개발본부");
    }
}
