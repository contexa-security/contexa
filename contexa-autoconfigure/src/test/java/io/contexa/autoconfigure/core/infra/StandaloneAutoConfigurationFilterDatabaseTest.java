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

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.annotation.AnnotatedGenericBeanDefinition;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DeferredImportSelector;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.env.MockEnvironment;

import javax.sql.DataSource;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's dependencies bring Spring Boot's database auto-configuration to every class path. Switched on or not, Contexa must not take
 * it from an application that has a database of its own, and must not let it fail an application that has none.
 */
class StandaloneAutoConfigurationFilterDatabaseTest {

    private static final String DATA_SOURCE = "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration";
    private static final String DATA_SOURCE_BOOT_4 = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration";
    private static final String PGVECTOR_STORE = "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration";
    private static final String HIBERNATE = "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration";
    /** What fails without a database, and after it what keeps out by its own condition. */
    private static final String[] DATABASE_SUPPORT = {DATA_SOURCE, DATA_SOURCE_BOOT_4, PGVECTOR_STORE, HIBERNATE};

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

    private static boolean[] decideDatabaseSupport(MockEnvironment environment) {
        return decideDatabaseSupport(environment, null);
    }

    private static boolean[] decideDatabaseSupport(MockEnvironment environment, BeanFactory beanFactory) {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter() {
            @Override
            boolean embeddedDatabasePresent() {
                return false;
            }
        };
        filter.setEnvironment(environment);
        if (beanFactory != null) {
            filter.setBeanFactory(beanFactory);
        }
        return filter.match(DATABASE_SUPPORT, null);
    }

    /** The annotation publishes this source when it switches Contexa on. */
    private static MockEnvironment switchedOn(MockEnvironment environment) {
        environment.getPropertySources().addFirst(new MapPropertySource(
                AiSecurityImportSelector.ACTIVATION_SOURCE, Map.of("contexa.ai.security.mode", "SANDBOX")));
        return environment;
    }

    /** A container hands the url over as an environment variable: no property name starts with {@code spring.datasource.} there. */
    private static MockEnvironment withDatabaseInAnEnvironmentVariable(MockEnvironment environment) {
        environment.getPropertySources().addLast(new SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                Map.<String, Object>of("SPRING_DATASOURCE_URL", "jdbc:postgresql://db/app")));
        return environment;
    }

    private static DefaultListableBeanFactory applicationWith(Class<?> configuration) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerBeanDefinition(configuration.getName(), new AnnotatedGenericBeanDefinition(configuration));
        return beanFactory;
    }

    /** PR-180: switched on, such an application did not start: Spring Boot asked for a url, Spring AI's pgvector store for a JdbcTemplate. */
    @Test
    void aSwitchedOnApplicationThatSaysNothingAboutADatabaseLosesWhatFailsWithoutOne() {
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment()))).containsExactly(false, false, false, true);
    }

    @Test
    void aSwitchedOnApplicationWithoutADatabaseLosesThemInDistributedModeAsWell() {
        MockEnvironment environment = switchedOn(new MockEnvironment().withProperty("contexa.infrastructure.mode", "distributed"));

        assertThat(decideDatabaseSupport(environment)).containsExactly(false, false, false, true);
    }

    @Test
    void aSwitchedOnApplicationThatSaysItHasADatabaseKeepsAllOfIt() {
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment().withProperty("spring.datasource.url", "jdbc:postgresql://db/app"))))
                .containsOnly(true);
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment().withProperty("spring.jpa.hibernate.ddl-auto", "validate"))))
                .containsOnly(true);
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment().withProperty("spring.liquibase.change-log", "classpath:db/changelog.xml"))))
                .containsOnly(true);
    }

    /** Contexa's database serves the application as well: Spring Boot's support works on that one data source. */
    @Test
    void aSwitchedOnApplicationWhoseDatabaseIsContexasKeepsAllOfIt() {
        MockEnvironment environment = switchedOn(new MockEnvironment()
                .withProperty("contexa.datasource.url", "jdbc:postgresql://db/contexa")
                .withProperty("contexa.datasource.isolation.contexa-owned-application", "true"));

        assertThat(decideDatabaseSupport(environment)).containsOnly(true);
    }

    /** Nothing gives Spring AI's pgvector store its JdbcTemplate in an application without a database, switched on or not. */
    @Test
    void anApplicationThatIsNotSwitchedOnLosesThePgvectorStoreWithoutADatabaseAndKeepsItWithOne() {
        assertThat(decideDatabaseSupport(new MockEnvironment())).containsExactly(false, false, false, true);
        assertThat(decideDatabaseSupport(new MockEnvironment().withProperty("spring.datasource.url", "jdbc:postgresql://db/app")))
                .containsOnly(true);
    }

    @Test
    void anApplicationThatNamesItsDatabaseInAnEnvironmentVariableKeepsAllOfIt() {
        assertThat(decideDatabaseSupport(withDatabaseInAnEnvironmentVariable(new MockEnvironment()))).containsOnly(true);
        assertThat(decideDatabaseSupport(switchedOn(withDatabaseInAnEnvironmentVariable(new MockEnvironment())))).containsOnly(true);
    }

    @Test
    void anApplicationThatBuildsItsDataSourceInCodeKeepsAllOfIt() {
        assertThat(decideDatabaseSupport(new MockEnvironment(), applicationWith(DataSourceInCode.class))).containsOnly(true);
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment()), applicationWith(DataSourceInCode.class))).containsOnly(true);
    }

    @Test
    void aDataSourceDeclaredByThePoolItReturnsCountsAsWell() {
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment()), applicationWith(PoolInCode.class))).containsOnly(true);
    }

    /** An application that declares one handles a database itself: what Spring Boot does around it is the application's, whatever the condition. */
    @Test
    void aDataSourceDeclaredUnderAConditionIsTheApplicationsWordAsWell() {
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment()), applicationWith(DataSourceUnderACondition.class))).containsOnly(true);
    }

    @Test
    void anApplicationWhoseConfigurationsBuildNoDataSourceStillLosesThem() {
        assertThat(decideDatabaseSupport(switchedOn(new MockEnvironment()), applicationWith(NoDatabaseInCode.class)))
                .containsExactly(false, false, false, true);
    }

    /**
     * Spring asks the filter while it handles deferred imports: by then it has registered the configurations it scanned, and none of the
     * beans they declare. This asks the filter at that very point.
     */
    @Test
    void theDataSourceOfAScannedConfigurationIsAlreadyInSightWhenSpringAsksTheFilter() {
        AskedAtImportTime.kept = null;

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ScanningApplication.class)) {
            assertThat(context.getBeansOfType(DataSource.class)).hasSize(1);
            assertThat(AskedAtImportTime.kept).containsOnly(true);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class DataSourceInCode {
        @Bean
        DataSource ordersDatabase() {
            return new DriverManagerDataSource("jdbc:postgresql://db/app");
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class PoolInCode {
        @Bean
        DriverManagerDataSource ordersDatabase() {
            return new DriverManagerDataSource("jdbc:postgresql://db/app");
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class DataSourceUnderACondition {
        @Bean
        @Profile("production")
        DataSource ordersDatabase() {
            return new DriverManagerDataSource("jdbc:postgresql://db/app");
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class NoDatabaseInCode {
        @Bean
        String greeting() {
            return "hello";
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ComponentScan(basePackageClasses = StandaloneAutoConfigurationFilterDatabaseTest.class, useDefaultFilters = false,
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = DataSourceInCode.class))
    @Import(AskedAtImportTime.class)
    static class ScanningApplication {
    }

    static class AskedAtImportTime implements DeferredImportSelector, BeanFactoryAware {

        static boolean[] kept;

        private BeanFactory beanFactory;

        @Override
        public void setBeanFactory(BeanFactory beanFactory) {
            this.beanFactory = beanFactory;
        }

        @Override
        public String[] selectImports(AnnotationMetadata importingClassMetadata) {
            kept = decideDatabaseSupport(new MockEnvironment(), this.beanFactory);
            return new String[0];
        }
    }

    private static final String BOOT_SECURITY = "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration";
    private static final String BOOT_AUTHORIZATION_SERVER =
            "org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration";

    private boolean[] decideSecurity(boolean applicationDeclaredSpringSecurity) {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter() {
            @Override
            boolean springSecurityPresent() {
                return applicationDeclaredSpringSecurity;
            }
        };
        filter.setEnvironment(new MockEnvironment());
        return filter.match(new String[] {BOOT_SECURITY, BOOT_AUTHORIZATION_SERVER}, null);
    }

    /** The starter carries OAuth2 libraries for Contexa: with only those, Boot's configurations fail in an application without Security. */
    @Test
    void anApplicationThatDidNotDeclareSpringSecurityGetsNoneOfBootsSecurityConfiguration() {
        assertThat(decideSecurity(false)).containsExactly(false, false);
    }

    /** It is the application's: removed here, its protection would be gone. */
    @Test
    void anApplicationThatDeclaredSpringSecurityKeepsBootsSecurityConfiguration() {
        assertThat(decideSecurity(true)).containsExactly(true, true);
    }
}
