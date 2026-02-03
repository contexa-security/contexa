package io.contexa.autoconfigure.core.streaming;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexacore.std.streaming.DefaultStandardStreamingService;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for StandardStreamingService.
 * Provides unified streaming API for Contexa platform.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.streaming", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(StreamingProperties.class)
public class CoreStreamingAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public StandardStreamingService standardStreamingService(
            StreamingProperties streamingProperties,
            ObjectMapper objectMapper) {
        return new DefaultStandardStreamingService(streamingProperties, objectMapper);
    }
}
