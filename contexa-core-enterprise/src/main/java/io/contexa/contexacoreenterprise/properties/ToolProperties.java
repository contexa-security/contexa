package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Tool 설정
 */
@Data
@ConfigurationProperties(prefix = "tool")
public class ToolProperties {

    /**
     * 캐시 설정
     */
    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();

    /**
     * 캐시 설정
     */
    @Data
    public static class CacheSettings {
        private boolean enabled = true;
        private int localMaxSize = 1000;
        private int defaultTtl = 300;
    }
}
