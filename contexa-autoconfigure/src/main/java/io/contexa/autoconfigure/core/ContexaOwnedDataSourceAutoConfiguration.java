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
        return properties.initializeDataSource();
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }
}
