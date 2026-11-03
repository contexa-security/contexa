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
package io.contexa.autoconfigure.iam.access;

import io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration;
import io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration;
import io.contexa.contexacore.autonomous.access.AccessEvaluationService;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.access.web.AccessEvaluationController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;

/**
 * docs/agent B4: the OpenID AuthZEN evaluation API ({@code contexa.security.zerotrust.authzen.enabled}, off by
 * default). It decides through the engine's synchronous decision path, so it comes after the autonomous
 * configurations that make that path.
 */
@AutoConfiguration(after = {CoreAutonomousAutoConfiguration.class, CoreAutonomousEventAutoConfiguration.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "contexa.security.zerotrust.authzen", name = "enabled", havingValue = "true")
@ConditionalOnBean({ZeroTrustEventPublisher.class, SynchronousProtectableDecisionService.class})
public class AccessEvaluationAutoConfiguration {

    @Bean(name = "contexaAccessEvaluationService")
    @ConditionalOnMissingBean
    public AccessEvaluationService accessEvaluationService(ZeroTrustEventPublisher events,
                                                           SynchronousProtectableDecisionService decisions,
                                                           ObjectProvider<SecurityZeroTrustProperties> properties) {
        return new AccessEvaluationService(events, decisions, properties.getIfAvailable(), null);
    }

    @Bean(name = "contexaAccessEvaluationController")
    @ConditionalOnMissingBean
    public AccessEvaluationController accessEvaluationController(AccessEvaluationService evaluations,
                                                                 ObjectProvider<SecurityZeroTrustProperties> properties) {
        SecurityZeroTrustProperties zeroTrust = properties.getIfAvailable();
        return new AccessEvaluationController(evaluations, zeroTrust != null ? zeroTrust.getAuthzen() : null);
    }
}
