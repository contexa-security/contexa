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
package io.contexa.autoconfigure.core.infra;

import com.legacyshop.scope.LegacySchedulerLockApplication;
import com.legacyshop.scope.LegacySchedulerLockApplication.HostJobs;
import com.legacyshop.scope.LegacySchedulerLockApplication.RecordingLockProvider;
import io.contexa.autoconfigure.core.infra.CoreSchedulerLockAutoConfigurationTest.ContexaJobs;
import io.contexa.autoconfigure.core.infra.CoreSchedulerLockAutoConfigurationTest.ContexaJobsDefinition;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The rows of the locks in a database: the scheduled work of Contexa writes its lock, by the name its annotation gives,
 * in Contexa's own table of Contexa's database, beside an application that has a lock provider of its own, and the
 * application's dormant lock is never written there (R-9 of docs/agent/운영모드-정상화-구현계획.md). Each run makes a
 * database of its own and drops it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class CoreSchedulerLockPostgresTest {

    private String database;

    @BeforeAll
    void createDatabase() {
        database = "contexa_lockscope_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(dataSource("postgres")).execute("create database " + database);
        new JdbcTemplate(dataSource(database)).execute("create table " + CoreSchedulerLockAutoConfiguration.LOCK_TABLE
                + " (name varchar(64) not null primary key, lock_until timestamp not null,"
                + " locked_at timestamp not null, locked_by varchar(255) not null)");
    }

    @AfterAll
    void dropDatabase() {
        if (database == null) {
            return;
        }
        JdbcTemplate admin = new JdbcTemplate(dataSource("postgres"));
        admin.queryForList("select pg_terminate_backend(pid) from pg_stat_activity where datname = ?", database);
        admin.execute("drop database if exists " + database);
    }

    @Test
    @DisplayName("Contexa 예약 작업의 잠금 행은 Contexa DB의 ctxa_shedlock에 주석의 이름 그대로 쌓이고, 앱의 잠금은 그곳에 쓰이지 않는다")
    void contexasLockRowIsInContexasTableByItsOwnNameAndTheApplicationsIsNot() {
        CoreSchedulerLockAutoConfigurationTest.runner(LegacySchedulerLockApplication.Dormant.class, ContexaJobsDefinition.class)
                .withBean("contexaDataSource", DataSource.class, () -> dataSource(database))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    ContexaJobs jobs = context.getBean(ContexaJobs.class);
                    HostJobs host = context.getBean(HostJobs.class);

                    jobs.retention();
                    host.nightly();

                    assertThat(jobs.runs()).isEqualTo(1);
                    assertThat(host.runs()).isEqualTo(1);
                    List<String> names = new JdbcTemplate(dataSource(database)).queryForList(
                            "select name from " + CoreSchedulerLockAutoConfiguration.LOCK_TABLE + " order by name", String.class);
                    assertThat(names).as("the rows of Contexa's lock table").containsExactly(ContexaJobs.LOCK);
                    assertThat(context.getBean("hostLockProvider", RecordingLockProvider.class).names())
                            .as("the application's own provider is asked for nothing").isEmpty();
                });
    }

    private static DriverManagerDataSource dataSource(String name) {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        int slash = url.lastIndexOf('/');
        return new DriverManagerDataSource(url.substring(0, slash + 1) + name, System.getenv("CONTEXA_TEST_DB_USERNAME"),
                System.getenv("CONTEXA_TEST_DB_PASSWORD"));
    }
}
