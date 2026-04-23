package io.contexa.autoconfigure.core;

import com.querydsl.jpa.impl.JPAQueryFactory;
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
import org.springframework.mock.env.MockEnvironment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionManager;

import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CoreDataAutoConfigurationTest {

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
    @DisplayName("Explicit Contexa Hibernate dialect should override JDBC URL inference")
    void explicitContexaHibernateDialectOverridesJdbcUrlInference() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment()
                .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa")
                .withProperty("contexa.jpa.properties.hibernate.dialect", "org.hibernate.dialect.H2Dialect"));

        LocalContainerEntityManagerFactoryBean factoryBean =
                configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

        assertThat(factoryBean.getJpaPropertyMap())
                .containsEntry("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
    }

    @Test
    @DisplayName("Contexa database-platform should configure Hibernate dialect")
    void contexaDatabasePlatformConfiguresHibernateDialect() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment()
                .withProperty("contexa.datasource.url", "jdbc:postgresql://localhost:5432/contexa")
                .withProperty("contexa.jpa.database-platform", "org.hibernate.dialect.H2Dialect"));

        LocalContainerEntityManagerFactoryBean factoryBean =
                configuration.contexaEntityManagerFactory(mock(DataSource.class), null);

        assertThat(factoryBean.getJpaPropertyMap())
                .containsEntry("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
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
                .withBean(io.contexa.contexaidentity.security.core.config.PlatformConfig.class,
                        () -> io.contexa.contexaidentity.security.core.config.PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=jdbc:h2:mem:application-metadata;DB_CLOSE_DELAY=-1",
                        "spring.datasource.driver-class-name=org.h2.Driver",
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
    @DisplayName("Application DataSource and EntityManagerFactory should coexist with Contexa datasource")
    void applicationJpaInfrastructureCoexistsWithContexaJpaInfrastructure() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestApplicationPackage.class)
                .withConfiguration(AutoConfigurations.of(
                        DataSourceAutoConfiguration.class,
                        HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(io.contexa.contexaidentity.security.core.config.PlatformConfig.class,
                        () -> io.contexa.contexaidentity.security.core.config.PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=jdbc:h2:mem:application;DB_CLOSE_DELAY=-1",
                        "spring.datasource.driver-class-name=org.h2.Driver",
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=jdbc:h2:mem:contexa;DB_CLOSE_DELAY=-1",
                        "contexa.datasource.driver-class-name=org.h2.Driver",
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
                .withBean(io.contexa.contexaidentity.security.core.config.PlatformConfig.class,
                        () -> io.contexa.contexaidentity.security.core.config.PlatformConfig.builder().build())
                .withBean(JPAQueryFactory.class, () -> mock(JPAQueryFactory.class))
                .withPropertyValues(
                        "spring.datasource.url=jdbc:h2:mem:application-defaults;DB_CLOSE_DELAY=-1",
                        "spring.datasource.driver-class-name=org.h2.Driver",
                        "spring.jpa.hibernate.ddl-auto=none",
                        "spring.sql.init.mode=never",
                        "contexa.datasource.url=jdbc:h2:mem:contexa-defaults;DB_CLOSE_DELAY=-1",
                        "contexa.datasource.driver-class-name=org.h2.Driver",
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

    @Configuration(proxyBeanMethods = false)
    @AutoConfigurationPackage
    static class TestApplicationPackage {
    }
}
