package io.contexa.demo.identity.configuration;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
@Profile("contexa")
public class IdentitySnapshotConfiguration {

    @Bean(name = "baselineDataSource", destroyMethod = "close")
    DataSource baselineDataSource(IdentityProperties identity, DataSourceProperties application) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(identity.baselineDbUrl());
        config.setUsername(application.getUsername());
        config.setPassword(application.getPassword());
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(3000);
        config.setPoolName("lab-identity-target");
        return new HikariDataSource(config);
    }

    @Bean(name = "baselineMigration", initMethod = "migrate")
    Flyway baselineMigration(@Qualifier("baselineDataSource") DataSource source) {
        return Flyway.configure().dataSource(source).locations("classpath:lab/db/migration")
                .schemas("lab").defaultSchema("lab").cleanDisabled(true).load();
    }

    @Bean(name = "baselineJdbc")
    @DependsOn("baselineMigration")
    JdbcOperations baselineJdbc(@Qualifier("baselineDataSource") DataSource source) {
        return new JdbcTemplate(source);
    }

    @Bean(name = "baselineTransactions")
    TransactionOperations baselineTransactions(@Qualifier("baselineDataSource") DataSource source) {
        return new TransactionTemplate(new JdbcTransactionManager(source));
    }
}
