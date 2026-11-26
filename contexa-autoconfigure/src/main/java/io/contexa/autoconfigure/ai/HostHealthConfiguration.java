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
package io.contexa.autoconfigure.ai;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 * Contexa's database stays out of the application's health unless it is the application's database too: then that
 * application's health keeps it. Whether it is, is the profile's answer for the application's data, which the activation
 * publishes (R-11 ① of docs/agent/운영모드-정상화-구현계획.md), in either mode and with either ownership.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(HealthContributorRegistry.class)
@ConditionalOnProperty(prefix = "contexa.datasource.isolation", name = "contexa-owned-application", havingValue = "false",
        matchIfMissing = true)
public class HostHealthConfiguration {

    @Bean(name = "contexaHostHealthWithoutContexaDatabase")
    @ConditionalOnMissingBean(name = "contexaHostHealthWithoutContexaDatabase")
    HostHealthWithoutContexaDatabase hostHealthWithoutContexaDatabase(ObjectProvider<HealthContributorRegistry> healthContributorRegistry,
                                                                     ListableBeanFactory beanFactory) {
        boolean theHostHasNoDatabase = Arrays.stream(BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, DataSource.class, true, false))
                .allMatch("contexaDataSource"::equals);
        return new HostHealthWithoutContexaDatabase(healthContributorRegistry.getIfAvailable(), theHostHasNoDatabase);
    }
}
