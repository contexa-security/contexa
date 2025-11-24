package io.contexa.contexaiam.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Security Step-Up Authentication 설정
 */
@Data
@ConfigurationProperties(prefix = "security.stepup")
public class SecurityStepUpProperties {

    /**
     * 최대 시도 횟수
     */
    private int maxAttempts = 3;

    /**
     * 잠금 시간 (초)
     */
    private int lockoutDuration = 300;
}
