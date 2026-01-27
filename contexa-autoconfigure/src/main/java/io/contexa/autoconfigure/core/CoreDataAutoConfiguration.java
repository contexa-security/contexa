package io.contexa.autoconfigure.core;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

@AutoConfiguration
@ConditionalOnClass(name = "jakarta.persistence.EntityManager")
@EnableJpaRepositories(basePackages = {
        "io.contexa.contexacommon.repository",
        "io.contexa.contexacore.repository",
        "io.contexa.contexaiam.repository"
})
@EntityScan(basePackages = {
        "io.contexa.contexacommon.entity",
        "io.contexa.contexacore.domain.entity",
        "io.contexa.contexaiam.domain.entity"
})
public class CoreDataAutoConfiguration {

    public CoreDataAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

        jdbcTemplate.setQueryTimeout(30);
        jdbcTemplate.setFetchSize(100);
        jdbcTemplate.setMaxRows(1000);

        return jdbcTemplate;
    }
}
