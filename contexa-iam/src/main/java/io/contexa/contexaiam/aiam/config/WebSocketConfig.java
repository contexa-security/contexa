
package io.contexa.contexaiam.aiam.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;
import org.springframework.http.server.ServerHttpRequest;

import java.security.Principal;
import java.util.Map;
import java.util.UUID;

@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
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
            SessionPrincipal p = new SessionPrincipal("sess-" + UUID.randomUUID());
            attributes.put("ws.principal", p);
            return p;
        }
    };

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.setApplicationDestinationPrefixes("/app"); // 클라 -> 서버
        config.enableSimpleBroker("/topic", "/queue");    // 서버 -> 클라
        config.setUserDestinationPrefix("/user");         // 사용자/세션 귀속
        log.info("Broker: app=/app, broker=/topic|/queue, user=/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws-soar")
                .setAllowedOriginPatterns("*")
                .setHandshakeHandler(handshakeHandler) // ★ 세션 Principal 부여
                .withSockJS();
        log.info("STOMP endpoint: /ws-soar");
    }

    // 운영: 풀은 넉넉히. (/user 라우팅으로 레이스 제거)
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
}

