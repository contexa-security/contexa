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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.mockito.Mockito.mock;

/**
 * What the flow of Contexa's administrators reads from the context while it is declared ({@link ContexaAdminFlow}), as a
 * running Contexa always has it: the identity settings and addresses, Contexa's JSON mapper and its one-time code service. A test that
 * runs {@link AiSecurityConfiguration} beside a configuration of flows of its own adds these, as the flow then joins it.
 */
@Configuration(proxyBeanMethods = false)
class ContexaAdminFlowBeans {

    @Bean
    AuthContextProperties authContextProperties() {
        return new AuthContextProperties();
    }

    @Bean
    AuthUrlProvider authUrlProvider(AuthContextProperties authContextProperties) {
        return new AuthUrlProvider(authContextProperties);
    }

    @Bean(name = "contexaObjectMapper")
    ObjectMapper contexaObjectMapper() {
        return new ObjectMapper();
    }

    @Bean(name = ContexaOneTimeTokens.BEAN_NAME)
    ContexaOneTimeTokens contexaOneTimeTokenService() {
        return new ContexaOneTimeTokens(mock(EmailOneTimeTokenService.class));
    }
}
