package io.contexa.demo.entry.configuration;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.contexa.demo.configuration.properties.LabProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
public class EntryPersistenceConfiguration {

    @Bean(name = "entryDataSource", destroyMethod = "close")
    DataSource entryDataSource(EntryProperties properties, LabProperties lab) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(properties.store().url());
        config.setUsername(properties.store().username());
        config.setPassword(properties.store().password());
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(3000);
        config.setInitializationFailTimeout(-1);
        config.setReadOnly(!"portal".equals(lab.role()));
        config.setPoolName("lab-entry");
        return new HikariDataSource(config);
    }

    @Bean(name = "entryJdbc")
    JdbcOperations entryJdbc(@Qualifier("entryDataSource") DataSource dataSource) {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.setQueryTimeout(3);
        return jdbc;
    }

    @Bean(name = "entryTransactions")
    TransactionOperations entryTransactions(@Qualifier("entryDataSource") DataSource dataSource) {
        return new TransactionTemplate(new JdbcTransactionManager(dataSource));
    }
}
