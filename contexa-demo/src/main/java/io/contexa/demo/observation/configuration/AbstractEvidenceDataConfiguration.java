package io.contexa.demo.observation.configuration;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

public abstract class AbstractEvidenceDataConfiguration {

    protected DataSource source(String name, String url, EvidenceStoreProperties properties) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(url);
        config.setUsername(properties.username());
        config.setPassword(properties.password());
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(2000);
        config.setInitializationFailTimeout(-1);
        config.setReadOnly(true);
        config.setPoolName("lab-evidence-" + name);
        return new HikariDataSource(config);
    }

    protected JdbcOperations jdbc(DataSource source) {
        JdbcTemplate jdbc = new JdbcTemplate(source);
        jdbc.setQueryTimeout(3);
        return jdbc;
    }
}
