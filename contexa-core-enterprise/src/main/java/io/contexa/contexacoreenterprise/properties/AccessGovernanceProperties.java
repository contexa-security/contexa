package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "access.governance")
public class AccessGovernanceProperties {
    private boolean enabled = true;
    @NestedConfigurationProperty
    private SearchSettings search = new SearchSettings();
    @NestedConfigurationProperty
    private RiskSettings risk = new RiskSettings();

    @Data
    public static class SearchSettings { private int limit = 20; }
    @Data
    public static class RiskSettings { private double threshold = 0.7; }
}
