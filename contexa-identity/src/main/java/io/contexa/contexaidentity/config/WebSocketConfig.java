package io.contexa.contexaidentity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.ServerHttpRequest;
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

import java.security.Principal;
import java.util.Map;
import java.util.UUID;


@Slf4j
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    
    static class SessionPrincipal implements Principal {
        private final String name;

        SessionPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    
    private final DefaultHandshakeHandler handshakeHandler = new DefaultHandshakeHandler() {
        @Override
        protected Principal determineUser(@NonNull ServerHttpRequest request,
                                          @NonNull WebSocketHandler wsHandler,
                                          @NonNull Map<String, Object> attributes) {
            Object existing = attributes.get("ws.principal");
            if (existing instanceof Principal) {
                return (Principal) existing;
            }

            SessionPrincipal principal = new SessionPrincipal("session-" + UUID.randomUUID());
            attributes.put("ws.principal", principal);
            log.debug("WebSocket 세션 Principal 생성: {}", principal.getName());
            return principal;
        }
    };

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        
        config.setApplicationDestinationPrefixes("/app");

        
        config.enableSimpleBroker("/topic", "/queue");

        
        config.setUserDestinationPrefix("/user");

        log.info("WebSocket Message Broker 설정 완료 - app=/app, broker=/topic|/queue, user=/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        
        registry.addEndpoint("/ws-soar")
                .setAllowedOriginPatterns("*")
                .setHandshakeHandler(handshakeHandler)
                .withSockJS();

        log.info("STOMP 엔드포인트 등록 완료: /ws-soar");
    }

    
    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        int processors = Runtime.getRuntime().availableProcessors();

        registration.taskExecutor()
                .corePoolSize(processors)
                .maxPoolSize(Math.max(8, processors * 2))
                .queueCapacity(10000)
                .keepAliveSeconds(60);

        registration.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                log.trace("인바운드 메시지: {}", message);
                return message;
            }
        });

        log.debug("WebSocket 인바운드 채널 설정 완료 - corePool={}, maxPool={}",
                  processors, Math.max(8, processors * 2));
    }

    
    @Override
    public void configureClientOutboundChannel(ChannelRegistration registration) {
        int processors = Runtime.getRuntime().availableProcessors();

        registration.taskExecutor()
                .corePoolSize(processors)
                .maxPoolSize(Math.max(8, processors * 2))
                .queueCapacity(10000)
                .keepAliveSeconds(60);

        registration.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                log.trace("아웃바운드 메시지: {}", message);
                return message;
            }
        });

        log.debug("WebSocket 아웃바운드 채널 설정 완료 - corePool={}, maxPool={}",
                  processors, Math.max(8, processors * 2));
    }
}
