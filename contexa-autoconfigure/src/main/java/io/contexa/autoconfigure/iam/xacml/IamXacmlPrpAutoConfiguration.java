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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.cache.ContexaCacheAutoConfiguration;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.prp.DatabasePolicyRetrievalPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@AutoConfiguration(after = ContexaCacheAutoConfiguration.class)
public class IamXacmlPrpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DatabasePolicyRetrievalPoint databasePolicyRetrievalPoint(
            PolicyRepository policyRepository,
            ContexaCacheService cacheService) {
        return new DatabasePolicyRetrievalPoint(policyRepository, cacheService);
    }
}

