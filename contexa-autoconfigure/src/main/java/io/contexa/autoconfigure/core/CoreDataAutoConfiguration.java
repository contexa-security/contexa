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

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import jakarta.persistence.EntityManagerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.DatabaseDriver;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@AutoConfiguration
@AutoConfigureAfter({DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
@ConditionalOnClass(name = "jakarta.persistence.EntityManager")
@ConditionalOnBean(PlatformConfig.class)
@EnableConfigurationProperties(ContexaDataSourceProperties.class)
@EnableJpaRepositories(basePackages = {
        "io.contexa.contexacommon.repository",
        "io.contexa.contexacore.repository",
        "io.contexa.contexaiam.repository"
}, entityManagerFactoryRef = "contexaEntityManagerFactory", transactionManagerRef = "contexaTransactionManager")
public class CoreDataAutoConfiguration implements EnvironmentAware {

    private static final List<String> DEFAULT_PACKAGES_TO_SCAN = List.of(
            "io.contexa.contexacommon.entity",
            "io.contexa.contexacore.domain.entity",
            "io.contexa.contexaiam.domain.entity");

    private Environment environment;

    public CoreDataAutoConfiguration() {
    }

    @Bean(name = "contexaDataSource", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaDataSource")
    public DataSource contexaDataSource(ContexaDataSourceProperties properties) {
        ContexaDataSourceIsolation.validate(properties, environment);
        return properties.initializeDataSourceBuilder().build();
    }

    @Bean(name = "contexaEntityManagerFactory", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaEntityManagerFactory")
    public LocalContainerEntityManagerFactoryBean contexaEntityManagerFactory(
            @Qualifier("contexaDataSource") DataSource dataSource,
            ObjectProvider<ContexaJpaManagedPackageProvider> packageProviders) {
        LocalContainerEntityManagerFactoryBean factoryBean = new LocalContainerEntityManagerFactoryBean();
        factoryBean.setDataSource(dataSource);
        factoryBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        factoryBean.setPersistenceUnitName("contexa");
        factoryBean.setPackagesToScan(packagesToScan(packageProviders));
        factoryBean.setJpaPropertyMap(jpaProperties());
        return factoryBean;
    }

    @Bean(name = "contexaTransactionManager", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaTransactionManager")
    public PlatformTransactionManager contexaTransactionManager(
            @Qualifier("contexaEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }

    @Bean(name = "contexaTransactionTemplate", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaTransactionTemplate")
    public TransactionTemplate contexaTransactionTemplate(
            @Qualifier("contexaTransactionManager") PlatformTransactionManager transactionManager) {
        return new TransactionTemplate(transactionManager);
    }

    @Bean
    @ConditionalOnMissingBean(TransactionTemplate.class)
    @ConditionalOnProperty(prefix = "contexa.datasource.isolation", name = "contexa-owned-application", havingValue = "true")
    public TransactionTemplate transactionTemplate(
            @Qualifier("contexaTransactionManager") PlatformTransactionManager transactionManager) {
        return new TransactionTemplate(transactionManager);
    }

    @Bean(name = "contexaJdbcTemplate", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaJdbcTemplate")
    public JdbcTemplate contexaJdbcTemplate(@Qualifier("contexaDataSource") DataSource dataSource) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

        jdbcTemplate.setQueryTimeout(30);
        jdbcTemplate.setFetchSize(100);
        jdbcTemplate.setMaxRows(1000);

        return jdbcTemplate;
    }

    @Bean
    @ConditionalOnMissingBean(JdbcTemplate.class)
    @ConditionalOnProperty(prefix = "contexa.datasource.isolation", name = "contexa-owned-application", havingValue = "true")
    public JdbcTemplate jdbcTemplate(@Qualifier("contexaDataSource") DataSource dataSource) {
        return contexaJdbcTemplate(dataSource);
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    private Map<String, Object> jpaProperties() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("hibernate.physical_naming_strategy",
                environment.getProperty(
                        "contexa.jpa.properties.hibernate.physical_naming_strategy",
                        "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy"));
        properties.put("hibernate.implicit_naming_strategy",
                environment.getProperty(
                        "contexa.jpa.properties.hibernate.implicit_naming_strategy",
                        "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        String ddlAuto = environment.getProperty("contexa.jpa.hibernate.ddl-auto");
        if (StringUtils.hasText(ddlAuto)) {
            properties.put("hibernate.hbm2ddl.auto", ddlAuto);
        }
        String defaultSchema = environment.getProperty("contexa.jpa.properties.hibernate.default_schema");
        if (StringUtils.hasText(defaultSchema)) {
            properties.put("hibernate.default_schema", defaultSchema);
        }
        String dialect = resolveHibernateDialect();
        if (StringUtils.hasText(dialect)) {
            properties.put("hibernate.dialect", dialect);
        }
        return properties;
    }

    private String resolveHibernateDialect() {
        String dialect = environment.getProperty("contexa.jpa.properties.hibernate.dialect");
        if (StringUtils.hasText(dialect)) {
            return dialect;
        }

        dialect = environment.getProperty("contexa.jpa.database-platform");
        if (StringUtils.hasText(dialect)) {
            return dialect;
        }

        String jdbcUrl = environment.getProperty("contexa.datasource.url");
        if (!StringUtils.hasText(jdbcUrl)) {
            return null;
        }

        DatabaseDriver databaseDriver = DatabaseDriver.fromJdbcUrl(jdbcUrl);
        return switch (databaseDriver) {
            case POSTGRESQL -> "org.hibernate.dialect.PostgreSQLDialect";
            case H2 -> "org.hibernate.dialect.H2Dialect";
            default -> null;
        };
    }

    private String[] packagesToScan(ObjectProvider<ContexaJpaManagedPackageProvider> packageProviders) {
        Set<String> packages = new LinkedHashSet<>(DEFAULT_PACKAGES_TO_SCAN);
        if (packageProviders != null) {
            packageProviders.orderedStream()
                    .map(ContexaJpaManagedPackageProvider::getPackagesToScan)
                    .filter(packageNames -> packageNames != null)
                    .flatMap(packageNames -> packageNames.stream())
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(packages::add);
        }

        String configuredPackages = environment.getProperty("contexa.jpa.packages-to-scan");
        if (StringUtils.hasText(configuredPackages)) {
            Arrays.stream(configuredPackages.split(","))
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(packages::add);
        }

        return packages.toArray(String[]::new);
    }
}
