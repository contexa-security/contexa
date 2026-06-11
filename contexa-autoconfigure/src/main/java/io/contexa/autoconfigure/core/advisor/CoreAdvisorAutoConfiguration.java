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
package io.contexa.autoconfigure.core.advisor;

import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacore.properties.ContexaAdvisorProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

import java.util.Collections;
import java.util.List;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaAdvisorProperties.class)
public class CoreAdvisorAutoConfiguration {

    @Autowired(required = false)
    private List<BaseAdvisor> baseAdvisors;

    @Bean
    @ConditionalOnMissingBean
    public AdvisorRegistry advisorRegistry() {
        AdvisorRegistry advisorRegistry = new AdvisorRegistry();
        List<BaseAdvisor> advisors = baseAdvisors == null ? Collections.emptyList() : baseAdvisors;
        advisors.forEach(advisorRegistry::register);
        return advisorRegistry;
    }

    @EventListener(ContextRefreshedEvent.class)
    public void onApplicationReady(ContextRefreshedEvent event) {
        event.getApplicationContext().getBean(AdvisorRegistry.class);
    }
}
