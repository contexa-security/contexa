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

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa on the class path but not switched on must not take Spring Boot's database auto-configuration from an application that has a
 * database of its own.
 */
class StandaloneAutoConfigurationFilterDatabaseTest {

    private static final String DATA_SOURCE = "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration";
    private static final String HIBERNATE = "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration";

    private boolean[] decide(MockEnvironment environment) {
        // an application with a database on a real server: no embedded database on its class path
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter() {
            @Override
            boolean embeddedDatabasePresent() {
                return false;
            }
        };
        filter.setEnvironment(environment);
        return filter.match(new String[] {DATA_SOURCE, HIBERNATE}, null);
    }

    @Test
    void anApplicationThatSaysItHasAJpaConfigurationKeepsSpringBootsDatabaseAutoConfiguration() {
        boolean[] kept = decide(new MockEnvironment().withProperty("spring.jpa.hibernate.ddl-auto", "validate"));

        assertThat(kept).containsExactly(true, true);
    }

    @Test
    void anApplicationThatSaysItHasFlywayOrLiquibaseKeepsThemToo() {
        assertThat(decide(new MockEnvironment().withProperty("spring.flyway.enabled", "true"))).containsExactly(true, true);
        assertThat(decide(new MockEnvironment().withProperty("spring.liquibase.change-log", "classpath:db/changelog.xml"))).containsExactly(true, true);
    }

    @Test
    void anApplicationThatSaysNothingAboutADatabaseAndHasNoEmbeddedOneStillLosesThemSoThatItDoesNotFailOnContexasDependencies() {
        // JPA keeps out by its own condition without a DataSource bean, and an application that builds one in code keeps JPA.
        assertThat(decide(new MockEnvironment())).containsExactly(false, true);
    }

    @Test
    void anApplicationWithAJndiNameKeepsThem() {
        assertThat(decide(new MockEnvironment().withProperty("spring.datasource.jndi-name", "java:comp/env/jdbc/app"))).containsExactly(true, true);
    }
}
