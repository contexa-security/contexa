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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;

/**
 * Static resources stay outside every security chain where Contexa is the application's main security configuration (mode
 * FULL). It is a setting of the whole application's security, which in mode SANDBOX stays the application's own, with
 * either ownership (R-11 of docs/agent/운영모드-정상화-구현계획.md).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnMode(SecurityMode.FULL)
public class IamFullModeInfrastructureConfiguration {

    @Bean(name = "contexaWebSecurityCustomizer")
    @ConditionalOnMissingBean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}
