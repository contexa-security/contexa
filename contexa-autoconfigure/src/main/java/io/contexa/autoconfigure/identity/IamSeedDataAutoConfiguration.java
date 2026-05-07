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
import org.springframework.beans.factory.annotation.Qualifier;
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

    static final String[] SEED_LOCATIONS = {
            "contexa/iam/data.sql",
            "contexa/iam/data-menu.sql",
            "contexa/iam/data-system-settings.sql"
    };

    @Bean
    public ApplicationRunner iamSeedDataRunner(@Qualifier("contexaDataSource") DataSource dataSource) {
        return (ApplicationArguments args) -> {
            for (String location : SEED_LOCATIONS) {
                Resource seed = new ClassPathResource(location);
                if (!seed.exists()) {
                    log.warn("[IamSeedData] classpath:{} not found, skipping", location);
                    continue;
                }
                ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
                populator.setContinueOnError(true);
                populator.addScript(seed);
                populator.execute(dataSource);
                log.info("[IamSeedData] {} executed", location);
            }
        };
    }
}
