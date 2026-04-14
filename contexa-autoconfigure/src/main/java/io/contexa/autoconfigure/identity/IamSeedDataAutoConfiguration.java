package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;

@Slf4j
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
@ConditionalOnClass(DataSource.class)
@ConditionalOnBean({DataSource.class, PlatformConfig.class})
@ConditionalOnProperty(prefix = "contexa.iam.seed", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamSeedDataAutoConfiguration {

    @Bean
    public ApplicationRunner iamSeedDataRunner(DataSource dataSource) {
        return (ApplicationArguments args) -> {
            Resource seed = new ClassPathResource("data.sql");
            if (!seed.exists()) {
                log.warn("[IamSeedData] classpath:data.sql not found, skipping seed");
                return;
            }
            var populator = new ResourceDatabasePopulator();
            populator.setContinueOnError(true);
            populator.addScript(seed);
            populator.execute(dataSource);
            log.info("[IamSeedData] data.sql executed");
        };
    }
}
