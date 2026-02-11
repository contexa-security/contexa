package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "governance")
public class GovernanceProperties {
    @NestedConfigurationProperty
    private AutoApproveSettings autoApprove = new AutoApproveSettings();
    @NestedConfigurationProperty
    private MultiApprovalSettings multiApproval = new MultiApprovalSettings();
    @NestedConfigurationProperty
    private CriticalSettings critical = new CriticalSettings();

    @Data
    public static class AutoApproveSettings {
        private boolean enabled = false;
        private String maxRisk = "LOW";
        private double minConfidence = 0.9;
    }
    @Data
    public static class MultiApprovalSettings { private String threshold = "MEDIUM"; }
    @Data
    public static class CriticalSettings { private int minApprovers = 3; }
}
