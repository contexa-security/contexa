package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.backpressure")
public class BackpressureProperties {

    private int maxConcurrentRequests = 100;
    private long timeoutMs = 5000;

    @NestedConfigurationProperty
    private CircuitBreakerSettings circuitBreaker = new CircuitBreakerSettings();

    @Data
    public static class CircuitBreakerSettings {
        private int failureRate = 50;
        private int waitDurationOpen = 60;
    }
}
