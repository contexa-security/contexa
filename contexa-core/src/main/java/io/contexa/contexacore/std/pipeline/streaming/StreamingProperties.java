package io.contexa.contexacore.std.pipeline.streaming;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for streaming pipeline.
 * Externalized configuration for streaming markers, timeouts, and retry settings.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "contexa.streaming")
public class StreamingProperties {

    private String finalResponseMarker = StreamingProtocol.FINAL_RESPONSE_MARKER;

    private String streamingMarker = StreamingProtocol.STREAMING_MARKER;

    private String jsonStartMarker = StreamingProtocol.JSON_START_MARKER;

    private String jsonEndMarker = StreamingProtocol.JSON_END_MARKER;

    private Duration timeout = Duration.ofMinutes(5);

    private int maxRetries = 3;

    private Duration retryDelay = Duration.ofSeconds(1);

    private double retryMultiplier = 1.5;

    private int markerBufferSize = 100;

    private boolean sentenceBufferingEnabled = true;
}
