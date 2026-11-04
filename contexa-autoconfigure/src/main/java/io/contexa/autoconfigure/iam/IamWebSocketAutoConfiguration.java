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

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.context.annotation.Import;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.List;

@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(PlatformConfig.class)
// An application that has any bean named like one of Spring's message broker beans runs a broker of its own, or uses the name for
// something else; Contexa's broker, which would define them again (and fail the application's start), stands aside and says so.
@Conditional(IamWebSocketAutoConfiguration.NoBrokerBeanNames.class)
@ConditionalOnProperty(prefix = "contexa.iam.websocket", name = "enabled",
        havingValue = "true", matchIfMissing = true)
@Import(WebSocketConfig.class)
public class IamWebSocketAutoConfiguration {

    static class NoBrokerBeanNames implements ConfigurationCondition {

        private static final List<String> NAMES = List.of(
                "clientInboundChannel", "clientOutboundChannel", "brokerChannel", "clientInboundChannelExecutor",
                "clientOutboundChannelExecutor", "brokerChannelExecutor", "messageBrokerTaskScheduler", "messageBrokerSockJsTaskScheduler",
                "brokerMessagingTemplate",
                "brokerMessageConverter", "simpAnnotationMethodMessageHandler", "simpleBrokerMessageHandler",
                "stompBrokerRelayMessageHandler", "userDestinationMessageHandler", "userRegistryMessageHandler",
                "userDestinationResolver", "userRegistry", "stompWebSocketHandlerMapping", "subProtocolWebSocketHandler",
                "webSocketScopeConfigurer", "webSocketMessageBrokerStats");

        @Override
        public ConfigurationPhase getConfigurationPhase() {
            return ConfigurationPhase.REGISTER_BEAN;
        }

        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            List<String> taken = NAMES.stream().filter(context.getBeanFactory()::containsBean).toList();
            if (!taken.isEmpty()) {
                log.warn("Contexa's console WebSocket (/ws-soar) is not started: the application has beans named {}, the names of Spring's message "
                        + "broker beans, which Contexa's broker would define again. Rename them, or switch the console WebSocket off with "
                        + "contexa.iam.websocket.enabled=false to silence this message.", taken);
            }
            return taken.isEmpty();
        }
    }
}

