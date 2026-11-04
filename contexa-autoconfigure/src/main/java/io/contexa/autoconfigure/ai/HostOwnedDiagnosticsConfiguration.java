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

import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** What an application that keeps its sign-in should hear about its chain at start. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(value = SecurityOwnershipMode.HOST_OWNED, matchIfUndeclared = true)
public class HostOwnedDiagnosticsConfiguration {

    @Bean(name = "contexaHostOwnedSecurityChainDiagnostics")
    @ConditionalOnMissingBean
    public HostOwnedSecurityChainDiagnostics hostOwnedSecurityChainDiagnostics(ConfigurableListableBeanFactory beanFactory) {
        return new HostOwnedSecurityChainDiagnostics(beanFactory);
    }
}
