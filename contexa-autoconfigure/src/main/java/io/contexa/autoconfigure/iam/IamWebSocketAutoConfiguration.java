package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;

/**
 * IAM WebSocket AutoConfiguration
 *
 * <p>
 * STOMP WebSocket 메시지 브로커 설정을 제공합니다.
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>WebSocketConfig - STOMP WebSocket 메시지 브로커 설정</li>
 * </ul>
 *
 * <h3>자동 설정 조건:</h3>
 * <ul>
 *   <li>Servlet 기반 웹 애플리케이션</li>
 * </ul>
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IamWebSocketAutoConfiguration {

    /**
     * STOMP WebSocket 메시지 브로커 설정
     *
     * <p>
     * WebSocket 엔드포인트 및 메시지 브로커 설정을 제공합니다:
     * </p>
     * <ul>
     *   <li>엔드포인트: /ws-soar (SockJS 지원)</li>
     *   <li>애플리케이션 목적지 프리픽스: /app</li>
     *   <li>브로커 목적지: /topic, /queue</li>
     *   <li>사용자 목적지 프리픽스: /user</li>
     * </ul>
     *
     * @return WebSocketConfig
     */
    @Bean
    @ConditionalOnMissingBean
    public WebSocketConfig webSocketConfig() {
        log.info("WebSocketConfig 빈 등록 (STOMP WebSocket 메시지 브로커)");
        return new WebSocketConfig();
    }
}
