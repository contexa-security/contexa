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

package io.contexa.contexaiam.aiam.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.messaging.support.AbstractSubscribableChannel;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.lang.NonNull;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurationSupport;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;
import org.springframework.http.server.ServerHttpRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Principal;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;

@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class WebSocketConfig extends WebSocketMessageBrokerConfigurationSupport {
    private static final Logger log = LoggerFactory.getLogger(WebSocketConfig.class);

    static class SessionPrincipal implements Principal {
        private final String name;
        SessionPrincipal(String name) { this.name = name; }
        @Override public String getName() { return name; }
    }

    private final DefaultHandshakeHandler handshakeHandler = new DefaultHandshakeHandler() {
        @Override
        protected Principal determineUser(@NonNull ServerHttpRequest request,
                                          @NonNull WebSocketHandler wsHandler,
                                          @NonNull Map<String, Object> attributes) {
            Object existing = attributes.get("ws.principal");
            if (existing instanceof Principal) return (Principal) existing;

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof Principal principal) {
                attributes.put("ws.principal", principal);
                return principal;
            }

            SessionPrincipal p = new SessionPrincipal("sess-" + UUID.randomUUID());
            attributes.put("ws.principal", p);
            return p;
        }
    };

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.setApplicationDestinationPrefixes("/app"); 
        config.enableSimpleBroker("/topic", "/queue");    
        config.setUserDestinationPrefix("/user");         
            }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws-soar")
                .setAllowedOriginPatterns("*")
                .addInterceptors(new AuthenticatedHandshakeInterceptor())
                .setHandshakeHandler(handshakeHandler)
                .withSockJS();
            }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.taskExecutor()
                .corePoolSize(Runtime.getRuntime().availableProcessors())
                .maxPoolSize(Math.max(8, Runtime.getRuntime().availableProcessors() * 2))
                .queueCapacity(10000)
                .keepAliveSeconds(60);
        registration.interceptors(new ChannelInterceptor() {
            @Override public Message<?> preSend(Message<?> message, MessageChannel channel) {
                return message;
            }
        });
    }

    @Override
    public void configureClientOutboundChannel(ChannelRegistration registration) {
        registration.taskExecutor()
                .corePoolSize(Runtime.getRuntime().availableProcessors())
                .maxPoolSize(Math.max(8, Runtime.getRuntime().availableProcessors() * 2))
                .queueCapacity(10000)
                .keepAliveSeconds(60);
        registration.interceptors(new ChannelInterceptor() {
            @Override public Message<?> preSend(Message<?> message, MessageChannel channel) {
                return message;
            }
        });
    }

    /*
     * The executors and the scheduler of the message broker are generic types (Executor, TaskExecutor, TaskScheduler). They are not
     * candidates for injection by type, so that an application's own executor, its default executor of Spring Boot and its @Scheduled
     * tasks never end up on the threads of Contexa's message broker. Spring's own wiring names them by qualifier.
     */
    @Bean(defaultCandidate = false)
    @Override
    public TaskExecutor clientInboundChannelExecutor() {
        return (TaskExecutor) super.clientInboundChannelExecutor();
    }

    @Bean(defaultCandidate = false)
    @Override
    public TaskExecutor clientOutboundChannelExecutor() {
        return (TaskExecutor) super.clientOutboundChannelExecutor();
    }

    @Bean(defaultCandidate = false)
    @Override
    public Executor brokerChannelExecutor(@Qualifier("clientInboundChannel") AbstractSubscribableChannel clientInboundChannel,
                                          @Qualifier("clientOutboundChannel") AbstractSubscribableChannel clientOutboundChannel) {
        return super.brokerChannelExecutor(clientInboundChannel, clientOutboundChannel);
    }

    @Bean(defaultCandidate = false)
    @Override
    public TaskScheduler messageBrokerTaskScheduler() {
        return super.messageBrokerTaskScheduler();
    }

    /** Spring asks for the scheduler by type here; the scheduler is not a candidate by type, so it is named. */
    @Bean
    @Override
    public HandlerMapping stompWebSocketHandlerMapping(
            @Qualifier("subProtocolWebSocketHandler") WebSocketHandler subProtocolWebSocketHandler,
            @Qualifier("messageBrokerTaskScheduler") TaskScheduler messageBrokerTaskScheduler,
            @Qualifier("clientInboundChannel") AbstractSubscribableChannel clientInboundChannel) {
        return super.stompWebSocketHandlerMapping(subProtocolWebSocketHandler, messageBrokerTaskScheduler, clientInboundChannel);
    }

    /** Only a signed-in user may open the connection: it serves the screens of the console, not the public. */
    static final class AuthenticatedHandshakeInterceptor implements HandshakeInterceptor {

        @Override
        public boolean beforeHandshake(@NonNull ServerHttpRequest request, @NonNull ServerHttpResponse response,
                                       @NonNull WebSocketHandler wsHandler, @NonNull Map<String, Object> attributes) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            boolean signedIn = authentication != null && authentication.isAuthenticated()
                    && !(authentication instanceof AnonymousAuthenticationToken);
            if (!signedIn) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
            }
            return signedIn;
        }

        @Override
        public void afterHandshake(@NonNull ServerHttpRequest request, @NonNull ServerHttpResponse response,
                                   @NonNull WebSocketHandler wsHandler, Exception exception) {
        }
    }
}

