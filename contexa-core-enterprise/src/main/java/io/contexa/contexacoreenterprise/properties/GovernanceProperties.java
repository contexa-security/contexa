package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.HashMap;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "governance")
public class GovernanceProperties {
    @NestedConfigurationProperty
    private AutoApproveSettings autoApprove = new AutoApproveSettings();
    @NestedConfigurationProperty
    private MultiApprovalSettings multiApproval = new MultiApprovalSettings();
    @NestedConfigurationProperty
    private CriticalSettings critical = new CriticalSettings();

    // Approver configuration per level: STANDARD=id:name:email, SENIOR=id:name:email, EXECUTIVE=id:name:email
    private Map<String, String> approvers = new HashMap<>();

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
