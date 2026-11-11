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
package io.contexa.autoconfigure.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import jakarta.persistence.EntityManagerFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionManager;

class CoreDataAutoConfigurationTest {

    private static final String[] PRODUCT_NAME_SETTINGS = {
            "hibernate.boot.allow_jdbc_metadata_access",
            "jakarta.persistence.database-product-name",
            "hibernate.jdbc.use_scrollable_resultset"
    };

    private static PostgresTestDatabase applicationDatabase;
    private static PostgresTestDatabase contexaDatabase;

    @BeforeAll
    static void startPostgres() {
        applicationDatabase = PostgresTestDatabase.empty();
        try {
            contexaDatabase = PostgresTestDatabase.empty();
        } catch (RuntimeException exception) {
            applicationDatabase.close();
            applicationDatabase = null;
            throw exception;
        }
    }

    @AfterAll
    static void stopPostgres() {
        try {
            if (contexaDatabase != null) {
                contexaDatabase.close();
            }
        } finally {
            if (applicationDatabase != null) {
                applicationDatabase.close();
            }
        }
    }

    @Test
    @DisplayName("Contexa EntityManagerFactory should use Spring-compatible Hibernate naming strategies")
    void contexaEntityManagerFactoryUsesSpringCompatibleNamingStrategies() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment()
                .withProperty("contexa.jpa.hibernate.ddl-auto", "validate")
                .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa"));

        LocalContainerEntityManagerFactoryBean factoryBean =
                configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

        assertThat(factoryBean.getJpaPropertyMap())
                .containsEntry("hibernate.physical_naming_strategy",
                        "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy")
                .containsEntry("hibernate.implicit_naming_strategy",
                        "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy")
                .containsEntry("hibernate.hbm2ddl.auto", "validate")
                .containsEntry("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
    }

    @Test
    @DisplayName("A PostgreSQL Contexa database settles the dialect from its product name, without reading the database")
    void aPostgresContexaDatabaseSettlesTheDialectFromItsProductName() {
        for (MockEnvironment environment : List.of(
                new MockEnvironment()
                        .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa"),
                new MockEnvironment()
                        .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa")
                        .withProperty("contexa.jpa.hibernate.ddl-auto", "none"))) {
            CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
            configuration.setEnvironment(environment);

            LocalContainerEntityManagerFactoryBean factoryBean =
                    configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

            assertThat(factoryBean.getJpaPropertyMap())
                    .doesNotContainKey("hibernate.dialect")
                    .containsEntry("hibernate.boot.allow_jdbc_metadata_access", "false")
                    .containsEntry("jakarta.persistence.database-product-name", "PostgreSQL")
                    .containsEntry("hibernate.jdbc.use_scrollable_resultset", "true");
        }
    }

    @Test
    @DisplayName("A Hibernate schema tool reads the database at start anyway, so its dialect stays named and read as before")
    void aSchemaToolKeepsTheNamedDialectReadFromTheDatabase() {
        for (String ddlAuto : List.of("validate", "update", "create", "create-drop", "create-only", "drop")) {
            CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
            configuration.setEnvironment(new MockEnvironment()
                    .withProperty("contexa.jpa.hibernate.ddl-auto", ddlAuto)
                    .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa"));

            LocalContainerEntityManagerFactoryBean factoryBean =
                    configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

            assertThat(factoryBean.getJpaPropertyMap()).as(ddlAuto)
                    .containsEntry("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect")
                    .doesNotContainKeys(PRODUCT_NAME_SETTINGS);
        }
    }

    @Test
    @DisplayName("An H2 Contexa database keeps its named dialect")
    void anH2ContexaDatabaseKeepsItsNamedDialect() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment()
                .withProperty("contexa.datasource.url", "jdbc:h2:mem:contexa"));

        LocalContainerEntityManagerFactoryBean factoryBean =
                configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

        assertThat(factoryBean.getJpaPropertyMap())
                .containsEntry("hibernate.dialect", "org.hibernate.dialect.H2Dialect")
                .doesNotContainKeys(PRODUCT_NAME_SETTINGS);
    }

    @Test
    @DisplayName("Explicit Contexa Hibernate dialect should override JDBC URL inference")
    void explicitContexaHibernateDialectOverridesJdbcUrlInference() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment()
                .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa")
                .withProperty("contexa.jpa.properties.hibernate.dialect", "com.example.ExplicitDialect"));

        LocalContainerEntityManagerFactoryBean factoryBean =
                configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

        assertThat(factoryBean.getJpaPropertyMap())
                .containsEntry("hibernate.dialect", "com.example.ExplicitDialect")
                .doesNotContainKeys(PRODUCT_NAME_SETTINGS);
    }

    @Test
    @DisplayName("Contexa database-platform should configure Hibernate dialect")
    void contexaDatabasePlatformConfiguresHibernateDialect() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment()
                .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa")
                .withProperty("contexa.jpa.database-platform", "com.example.ExplicitDialect"));

        LocalContainerEntityManagerFactoryBean factoryBean =
                configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

        assertThat(factoryBean.getJpaPropertyMap())
                .containsEntry("hibernate.dialect", "com.example.ExplicitDialect")
                .doesNotContainKeys(PRODUCT_NAME_SETTINGS);
    }

    @Test
    @DisplayName("Contexa EntityManagerFactory should not require JDBC metadata to determine PostgreSQL dialect")
    void contexaEntityManagerFactoryDoesNotRequireJdbcMetadataForPostgresDialect() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestApplicationPackage.class)
                .withConfiguration(AutoConfigurations.of(
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class,
                        () -> PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=" + applicationDatabase.dataSource().getJdbcUrl(),
                        "spring.datasource.username=" + applicationDatabase.dataSource().getUsername(),
                        "spring.datasource.password=" + applicationDatabase.dataSource().getPassword(),
                        "spring.datasource.driver-class-name=org.postgresql.Driver",
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=jdbc:postgresql://127.0.0.1:1/contexa",
                        "contexa.datasource.driver-class-name=org.postgresql.Driver",
                        "contexa.jpa.hibernate.ddl-auto=none")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("contexaEntityManagerFactory");
                });
    }

    @Test
    @DisplayName("Core data auto-configuration should not globally extend application entity scan")
    void coreDataAutoConfigurationDoesNotDeclareGlobalEntityScan() {
        assertThat(CoreDataAutoConfiguration.class.getAnnotation(EntityScan.class)).isNull();
    }

    @Test
    @DisplayName("Core data auto-configuration should not turn Spring Data JPA auditing on for the application")
    void coreDataAutoConfigurationDoesNotActivateJpaAuditing() throws Exception {
        String imports = readAutoConfigurationImports();

        assertThat(imports).doesNotContain("JpaAuditingConfig");
    }

    @Test
    @DisplayName("Application DataSource and EntityManagerFactory should coexist with Contexa datasource")
    void applicationJpaInfrastructureCoexistsWithContexaJpaInfrastructure() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestApplicationPackage.class)
                .withConfiguration(AutoConfigurations.of(
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class,
                        () -> PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=" + applicationDatabase.dataSource().getJdbcUrl(),
                        "spring.datasource.username=" + applicationDatabase.dataSource().getUsername(),
                        "spring.datasource.password=" + applicationDatabase.dataSource().getPassword(),
                        "spring.datasource.driver-class-name=org.postgresql.Driver",
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=" + contexaDatabase.dataSource().getJdbcUrl(),
                        "contexa.datasource.username=" + contexaDatabase.dataSource().getUsername(),
                        "contexa.datasource.password=" + contexaDatabase.dataSource().getPassword(),
                        "contexa.datasource.driver-class-name=org.postgresql.Driver",
                        "contexa.jpa.hibernate.ddl-auto=none")
                .run(context -> {
                    assertThat(context).hasBean("dataSource");
                    assertThat(context).hasBean("entityManagerFactory");
                    assertThat(context).hasBean("contexaDataSource");
                    assertThat(context).hasBean("contexaEntityManagerFactory");
                });
    }

    @Test
    @DisplayName("Contexa data infrastructure should not become the application's unqualified default")
    void contexaInfrastructureDoesNotPolluteApplicationDefaultInfrastructure() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestApplicationPackage.class)
                .withConfiguration(AutoConfigurations.of(
                        DataSourceAutoConfiguration.class,
                        JdbcTemplateAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class,
                        () -> PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=" + applicationDatabase.dataSource().getJdbcUrl(),
                        "spring.datasource.username=" + applicationDatabase.dataSource().getUsername(),
                        "spring.datasource.password=" + applicationDatabase.dataSource().getPassword(),
                        "spring.datasource.driver-class-name=org.postgresql.Driver",
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=" + contexaDatabase.dataSource().getJdbcUrl(),
                        "contexa.datasource.username=" + contexaDatabase.dataSource().getUsername(),
                        "contexa.datasource.password=" + contexaDatabase.dataSource().getPassword(),
                        "contexa.datasource.driver-class-name=org.postgresql.Driver",
                        "contexa.jpa.hibernate.ddl-auto=none")
                .run(context -> {
                    assertThat(context).hasBean("dataSource");
                    assertThat(context).hasBean("entityManagerFactory");
                    assertThat(context).hasBean("transactionManager");
                    assertThat(context).hasBean("jdbcTemplate");
                    assertThat(context).hasBean("contexaDataSource");
                    assertThat(context).hasBean("contexaEntityManagerFactory");
                    assertThat(context).hasBean("contexaTransactionManager");
                    assertThat(context).hasBean("contexaJdbcTemplate");

                    assertThat(context.getBean(DataSource.class))
                            .isSameAs(context.getBean("dataSource", DataSource.class));
                    assertThat(context.getBean(EntityManagerFactory.class))
                            .isSameAs(context.getBean("entityManagerFactory", EntityManagerFactory.class));
                    assertThat(context.getBean(TransactionManager.class))
                            .isSameAs(context.getBean("transactionManager", PlatformTransactionManager.class));
                    assertThat(context.getBean(JdbcTemplate.class))
                            .isSameAs(context.getBean("jdbcTemplate", JdbcTemplate.class));
                });
    }

    @Test
    @DisplayName("Core data configuration should coexist with the application's own JPA auditing")
    void coreDataConfigurationCoexistsWithTheApplicationsOwnJpaAuditing() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestApplicationPackage.class, ApplicationAuditing.class)
                .withConfiguration(AutoConfigurations.of(
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class,
                        () -> PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=" + applicationDatabase.dataSource().getJdbcUrl(),
                        "spring.datasource.username=" + applicationDatabase.dataSource().getUsername(),
                        "spring.datasource.password=" + applicationDatabase.dataSource().getPassword(),
                        "spring.datasource.driver-class-name=org.postgresql.Driver",
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=" + contexaDatabase.dataSource().getJdbcUrl(),
                        "contexa.datasource.username=" + contexaDatabase.dataSource().getUsername(),
                        "contexa.datasource.password=" + contexaDatabase.dataSource().getPassword(),
                        "contexa.datasource.driver-class-name=org.postgresql.Driver",
                        "contexa.jpa.hibernate.ddl-auto=none")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("jpaAuditingHandler");
                });
    }

    @Test
    @DisplayName("Contexa-owned applications should boot with only contexa.datasource")
    void contexaOwnedApplicationUsesContexaDatasourceAsDefaultWhenSpringDatasourceIsAbsent() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestApplicationPackage.class)
                .withConfiguration(AutoConfigurations.of(
                        ContexaOwnedDataSourceAutoConfiguration.class,
                        DataSourceAutoConfiguration.class,
                        JdbcTemplateAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class,
                        () -> PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=" + contexaDatabase.dataSource().getJdbcUrl(),
                        "contexa.datasource.username=" + contexaDatabase.dataSource().getUsername(),
                        "contexa.datasource.password=" + contexaDatabase.dataSource().getPassword(),
                        "contexa.datasource.driver-class-name=org.postgresql.Driver",
                        "contexa.datasource.isolation.contexa-owned-application=true",
                        "contexa.jpa.hibernate.ddl-auto=none")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("dataSource");
                    assertThat(context).hasBean("contexaDataSource");
                    assertThat(context.getBean("dataSource", DataSource.class))
                            .isSameAs(context.getBean("contexaDataSource", DataSource.class));
                });
    }

    private static String readAutoConfigurationImports() throws IOException {
        return Files.readString(
                Path.of("src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"),
                StandardCharsets.UTF_8);
    }

    @Configuration(proxyBeanMethods = false)
    @AutoConfigurationPackage
    static class TestApplicationPackage {
    }

    /** The application's own Spring Data auditing, which Contexa must leave as it is. */
    @Configuration(proxyBeanMethods = false)
    @EnableJpaAuditing
    static class ApplicationAuditing {
    }
}
