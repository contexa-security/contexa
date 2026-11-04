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
package io.contexa.autoconfigure.ai;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.CompositeHealthContributor;
import org.springframework.boot.actuate.health.DefaultHealthContributorRegistry;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthContributor;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.NamedContributor;
import org.springframework.boot.actuate.jdbc.DataSourceHealthIndicator;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class HostHealthWithoutContexaDatabaseTest {

    private final HealthContributor contexa = new DataSourceHealthIndicator(mock(DataSource.class));
    private final HealthContributor host = new DataSourceHealthIndicator(mock(DataSource.class));
    private final HealthContributor reports = new DataSourceHealthIndicator(mock(DataSource.class));
    private final HealthContributor ping = (HealthIndicator) () -> Health.up().build();

    private HealthContributorRegistry registryWith(HealthContributor db) {
        Map<String, HealthContributor> contributors = new LinkedHashMap<>();
        contributors.put("ping", ping);
        if (db != null) {
            contributors.put("db", db);
        }
        return new DefaultHealthContributorRegistry(contributors);
    }

    private static void standAside(HealthContributorRegistry registry) {
        new HostHealthWithoutContexaDatabase(registry, false).afterSingletonsInstantiated();
    }

    private static HealthContributor composite(Map<String, HealthContributor> members) {
        return CompositeHealthContributor.fromMap(new LinkedHashMap<>(members));
    }

    @Test
    void aHostWithOneDatabaseGetsTheHealthItHasAlone() {
        HealthContributorRegistry registry = registryWith(composite(Map.of("contexaDataSource", contexa, "dataSource", host)));

        standAside(registry);

        assertThat(registry.getContributor("db")).isSameAs(host);
    }

    @Test
    void aHostWithSeveralDatabasesKeepsThemAll() {
        HealthContributorRegistry registry = registryWith(composite(Map.of("contexaDataSource", contexa, "dataSource", host, "reports", reports)));

        standAside(registry);

        HealthContributor db = registry.getContributor("db");
        assertThat(db).isInstanceOf(CompositeHealthContributor.class);
        List<String> names = new ArrayList<>();
        for (NamedContributor<HealthContributor> member : (CompositeHealthContributor) db) {
            names.add(member.getName());
        }
        assertThat(names).containsExactlyInAnyOrder("dataSource", "reports");
    }

    @Test
    void aHostWithoutADatabaseHasNoDatabaseHealth() {
        HealthContributorRegistry registry = registryWith(contexa);

        new HostHealthWithoutContexaDatabase(registry, true).afterSingletonsInstantiated();

        assertThat(registry.getContributor("db")).isNull();
        assertThat(registry.getContributor("ping")).isSameAs(ping);
    }

    @Test
    void theHostsOwnSingleDatabaseIsLeftAlone() {
        HealthContributorRegistry registry = registryWith(host);

        standAside(registry);

        assertThat(registry.getContributor("db")).isSameAs(host);
    }

    @Test
    void anIndicatorTheHostWroteItselfIsLeftAloneEvenWithoutADatabase() {
        HealthContributorRegistry registry = registryWith(ping);

        new HostHealthWithoutContexaDatabase(registry, true).afterSingletonsInstantiated();

        assertThat(registry.getContributor("db")).isSameAs(ping);
    }

    @Test
    void aCompositeWithoutContexaIsLeftAlone() {
        HealthContributor db = composite(Map.of("dataSource", host, "reports", reports));
        HealthContributorRegistry registry = registryWith(db);

        standAside(registry);

        assertThat(registry.getContributor("db")).isSameAs(db);
    }

    @Test
    void aHostWithoutHealthIsNothingToDo() {
        new HostHealthWithoutContexaDatabase(null, false).afterSingletonsInstantiated();
    }
}
