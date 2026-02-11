package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.UUID;

@Data
@ConfigurationProperties(prefix = "security.state")
public class StateProperties {
    private int ttlSeconds = 3600;
    private String instanceId = UUID.randomUUID().toString();
    @NestedConfigurationProperty
    private ChangesSettings changes = new ChangesSettings();

    @Data
    public static class ChangesSettings {
        private String channel = "state:changes";
    }
}
