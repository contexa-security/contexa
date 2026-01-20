package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
@ConfigurationProperties(prefix = "tool")
public class ToolProperties {

    
    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();

    
    @Data
    public static class CacheSettings {
        private boolean enabled = true;
        private int localMaxSize = 1000;
        private int defaultTtl = 300;
    }
}
