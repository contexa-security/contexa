package io.contexa.autoconfigure.core;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

@AutoConfiguration(before = DataSourceAutoConfiguration.class)
@ConditionalOnClass(DataSource.class)
@ConditionalOnProperty(prefix = "contexa.datasource.isolation", name = "contexa-owned-application", havingValue = "true")
@EnableConfigurationProperties(ContexaDataSourceProperties.class)
public class ContexaOwnedDataSourceAutoConfiguration implements EnvironmentAware {

    private Environment environment;

    @Bean(name = {"dataSource", "contexaDataSource"})
    @ConditionalOnMissingBean(DataSource.class)
    public DataSource contexaOwnedDataSource(ContexaDataSourceProperties properties) {
        ContexaDataSourceIsolation.validate(properties, environment);
        return properties.initializeDataSourceBuilder().build();
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }
}
