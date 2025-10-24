package io.contexa.contexacore.config.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import java.time.Duration;

/**
 * Custom Jackson module for AI3Security-specific serialization/deserialization
 */
public class CustomJacksonModule extends SimpleModule {

    public CustomJacksonModule() {
        super("AI3SecurityJacksonModule");

        // Register custom Duration deserializer
        addDeserializer(Duration.class, new CustomDurationDeserializer());
    }
}