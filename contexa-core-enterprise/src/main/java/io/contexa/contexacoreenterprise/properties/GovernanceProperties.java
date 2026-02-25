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

    @NestedConfigurationProperty
    private RiskWeightSettings riskWeights = new RiskWeightSettings();

    @NestedConfigurationProperty
    private ApprovalSettings approval = new ApprovalSettings();

    @Data
    public static class AutoApproveSettings {
        private boolean enabled = false;
        private String maxRisk = "LOW";
        private double minConfidence = 0.9;
    }
    @Data
    public static class MultiApprovalSettings { private String threshold = "MEDIUM"; }
    @Data
    public static class CriticalSettings {
        private int minApprovers = 3;
        private int highApprovers = 2;
    }

    @Data
    public static class ApprovalSettings {
        private int expiryDays = 3;
        private int workflowTtlDays = 7;
        private String defaultEmail = "approver@contexa.com";
    }

    @Data
    public static class RiskWeightSettings {
        // Proposal type weights
        private double deletePolicyWeight = 0.2;
        private double createPolicyWeight = 0.12;
        private double updatePolicyWeight = 0.06;
        private double defaultTypeWeight = 0.03;

        // Confidence-based adjustments
        private double lowConfidenceWeight = 0.2;
        private double mediumConfidenceWeight = 0.05;
        private double highConfidenceReduction = 0.1;

        // Impact and learning type weights
        private double highImpactWeight = 0.1;
        private double highImpactThreshold = 0.8;
        private double threatResponseWeight = 0.06;
        private double accessPatternWeight = 0.03;

        // Risk level adjustment thresholds
        private double majorUpThreshold = 0.6;
        private double minorUpThreshold = 0.4;
    }
}
