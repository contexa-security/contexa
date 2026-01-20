package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Import;


@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Import(WebSocketConfig.class)
public class IamWebSocketAutoConfiguration {
    
    
}
