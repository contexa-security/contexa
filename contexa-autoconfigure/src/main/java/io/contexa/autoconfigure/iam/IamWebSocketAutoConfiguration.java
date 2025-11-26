package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Import;

/**
 * IAM WebSocket AutoConfiguration
 *
 * <p>
 * STOMP WebSocket 메시지 브로커 설정을 제공합니다.
 * @Import를 사용하여 WebSocketConfig를 Configuration으로 로드합니다.
 * 이렇게 해야 @EnableWebSocketMessageBroker가 Spring에 의해 처리되어
 * brokerMessagingTemplate 빈이 생성됩니다.
 * </p>
 *
 * <h3>Import되는 설정:</h3>
 * <ul>
 *   <li>WebSocketConfig - STOMP WebSocket 메시지 브로커 설정</li>
 * </ul>
 *
 * <h3>WebSocketConfig가 제공하는 설정:</h3>
 * <ul>
 *   <li>엔드포인트: /ws-soar (SockJS 지원)</li>
 *   <li>애플리케이션 목적지 프리픽스: /app</li>
 *   <li>브로커 목적지: /topic, /queue</li>
 *   <li>사용자 목적지 프리픽스: /user</li>
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
@Import(WebSocketConfig.class)
public class IamWebSocketAutoConfiguration {
    // @Import가 WebSocketConfig를 Configuration으로 로드하여
    // @EnableWebSocketMessageBroker가 활성화되고 brokerMessagingTemplate 빈이 생성됨
}
