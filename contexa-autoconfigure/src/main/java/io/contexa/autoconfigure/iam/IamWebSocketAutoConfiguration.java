package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * IAM WebSocket AutoConfiguration
 *
 * STOMP WebSocket 설정
 */
@AutoConfiguration
@Import(WebSocketConfig.class)
public class IamWebSocketAutoConfiguration {
}
