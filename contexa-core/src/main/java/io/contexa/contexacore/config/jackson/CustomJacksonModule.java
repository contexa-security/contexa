package io.contexa.contexacore.config.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import java.time.Duration;


public class CustomJacksonModule extends SimpleModule {

    public CustomJacksonModule() {
        super("contexaJacksonModule");

        
        addDeserializer(Duration.class, new CustomDurationDeserializer());
    }
}