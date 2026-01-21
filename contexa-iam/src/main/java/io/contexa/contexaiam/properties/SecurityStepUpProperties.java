package io.contexa.contexaiam.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.stepup")
public class SecurityStepUpProperties {

    private int maxAttempts = 3;

    private int lockoutDuration = 300;
}
