package io.contexa.contexacore.config.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import java.time.Duration;

/**
 * Custom Jackson module for contexa-specific serialization/deserialization
 */
public class CustomJacksonModule extends SimpleModule {

    public CustomJacksonModule() {
        super("contexaJacksonModule");

        // Register custom Duration deserializer
        addDeserializer(Duration.class, new CustomDurationDeserializer());
    }
}