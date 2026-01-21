package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.coldpath")
public class SecurityColdPathProperties {

    @NestedConfigurationProperty
    private ConfidenceSettings confidence = new ConfidenceSettings();

    @Data
    public static class ConfidenceSettings {
        private double layer1Base = 0.5;
        private double layer2Base = 0.7;  
    }
}
