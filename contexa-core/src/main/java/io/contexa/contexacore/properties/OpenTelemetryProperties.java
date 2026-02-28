package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "contexa.opentelemetry")
public class OpenTelemetryProperties {
    private boolean enabled = true;
    private String serviceName = "contexa-core";
    private String exporterEndpoint = "http://localhost:4317";
    private double samplingProbability = 1.0;
}
