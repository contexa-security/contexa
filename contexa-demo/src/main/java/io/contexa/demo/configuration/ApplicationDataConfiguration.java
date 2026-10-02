package io.contexa.demo.configuration;

import com.zaxxer.hikari.HikariDataSource;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
public class ApplicationDataConfiguration {

    @Bean(name = "flyway", initMethod = "migrate")
    Flyway applicationMigration(@Qualifier("dataSource") DataSource source,
            @Value("${spring.flyway.locations}") String[] locations) {
        return Flyway.configure().dataSource(source).locations(locations)
                .schemas("lab").defaultSchema("lab").cleanDisabled(true).load();
    }

    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource")
    DataSourceProperties labDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean(name = "dataSource", destroyMethod = "close")
    @Primary
    @ConfigurationProperties("spring.datasource.hikari")
    HikariDataSource labApplicationDataSource(@Qualifier("labDataSourceProperties") DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
    }

    @Bean(name = "applicationTransactions")
    TransactionOperations applicationTransactions(@Qualifier("dataSource") DataSource source) {
        return new TransactionTemplate(new JdbcTransactionManager(source));
    }

    @Bean(name = "jdbcTemplate")
    @Primary
    JdbcTemplate applicationJdbc(@Qualifier("dataSource") DataSource source) {
        JdbcTemplate jdbc = new JdbcTemplate(source);
        jdbc.setQueryTimeout(5);
        return jdbc;
    }
}
