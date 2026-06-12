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
package io.contexa.autoconfigure.identity;

import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
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
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;

@Slf4j
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, CoreDataAutoConfiguration.class})
@ConditionalOnClass(DataSource.class)
@ConditionalOnBean(value = PlatformConfig.class, name = "contexaDataSource")
@ConditionalOnProperty(prefix = "contexa.iam.seed", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamSeedDataAutoConfiguration {

    static final String[] SEED_LOCATIONS = {
            "db/data.sql",
            "db/data-menu.sql",
            "db/data-system-settings.sql"
    };

    @Bean
    @Order(10)
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
