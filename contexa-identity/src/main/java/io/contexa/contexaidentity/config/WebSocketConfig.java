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

/**
 * WebSocket 설정
 *
 * SoarApprovalNotifier가 사용하는 SimpMessagingTemplate Bean을 생성합니다.
 * @EnableWebSocketMessageBroker 어노테이션이 AbstractMessageBrokerConfiguration을 활성화하여
 * brokerMessagingTemplate Bean을 자동 등록합니다.
 */
@Slf4j
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    /**
     * 세션 기반 Principal 구현
     */
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

    /**
     * 핸드셰이크 시 세션 Principal 자동 생성
     */
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
        // 클라이언트 → 서버 메시지 접두사
        config.setApplicationDestinationPrefixes("/app");

        // 서버 → 클라이언트 브로드캐스트 접두사
        config.enableSimpleBroker("/topic", "/queue");

        // 사용자/세션별 메시지 접두사
        config.setUserDestinationPrefix("/user");

        log.info("WebSocket Message Broker 설정 완료 - app=/app, broker=/topic|/queue, user=/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // SOAR 승인 알림용 WebSocket 엔드포인트
        registry.addEndpoint("/ws-soar")
                .setAllowedOriginPatterns("*")
                .setHandshakeHandler(handshakeHandler)
                .withSockJS();

        log.info("STOMP 엔드포인트 등록 완료: /ws-soar");
    }

    /**
     * 클라이언트 → 서버 인바운드 채널 설정
     */
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

    /**
     * 서버 → 클라이언트 아웃바운드 채널 설정
     */
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
