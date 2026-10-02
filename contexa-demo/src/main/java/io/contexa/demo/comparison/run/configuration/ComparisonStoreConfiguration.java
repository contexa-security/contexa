package io.contexa.demo.comparison.run.configuration;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.contexa.demo.entry.configuration.EntryProperties;
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
public class ComparisonStoreConfiguration {

    @Bean(name = "comparisonDataSource", destroyMethod = "close")
    DataSource comparisonDataSource(EntryProperties properties) {
        HikariConfig configuration = new HikariConfig();
        configuration.setJdbcUrl(properties.store().url());
        configuration.setUsername(properties.store().username());
        configuration.setPassword(properties.store().password());
        configuration.setPoolName("lab-comparison-commands");
        configuration.setMaximumPoolSize(2);
        configuration.setMinimumIdle(0);
        configuration.setConnectionTimeout(3000);
        configuration.setInitializationFailTimeout(-1);
        return new HikariDataSource(configuration);
    }

    @Bean(name = "comparisonJdbc")
    JdbcOperations comparisonJdbc(@Qualifier("comparisonDataSource") DataSource source) {
        JdbcTemplate jdbc = new JdbcTemplate(source);
        jdbc.setQueryTimeout(3);
        return jdbc;
    }

    @Bean(name = "comparisonTransactions")
    TransactionOperations comparisonTransactions(@Qualifier("comparisonDataSource") DataSource source) {
        return new TransactionTemplate(new JdbcTransactionManager(source));
    }
}
