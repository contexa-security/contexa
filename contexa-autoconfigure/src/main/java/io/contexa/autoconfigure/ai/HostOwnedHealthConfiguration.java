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

import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.util.Arrays;

/** Where Contexa owns the sign-in its database is the application's own, so that application's health keeps it. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(HealthContributorRegistry.class)
@ConditionalOnOwnership(value = SecurityOwnershipMode.HOST_OWNED, matchIfUndeclared = true)
public class HostOwnedHealthConfiguration {

    @Bean(name = "contexaHostHealthWithoutContexaDatabase")
    @ConditionalOnMissingBean(name = "contexaHostHealthWithoutContexaDatabase")
    HostHealthWithoutContexaDatabase hostHealthWithoutContexaDatabase(ObjectProvider<HealthContributorRegistry> healthContributorRegistry,
                                                                     ListableBeanFactory beanFactory) {
        boolean theHostHasNoDatabase = Arrays.stream(BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, DataSource.class, true, false))
                .allMatch("contexaDataSource"::equals);
        return new HostHealthWithoutContexaDatabase(healthContributorRegistry.getIfAvailable(), theHostHasNoDatabase);
    }
}
