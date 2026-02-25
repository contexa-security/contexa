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
    private ApproverCountSettings approverCount = new ApproverCountSettings();
    @NestedConfigurationProperty
    private RejectionSettings rejection = new RejectionSettings();

    // Approver configuration per level: STANDARD=id:name:email, SENIOR=id:name:email, EXECUTIVE=id:name:email
    private Map<String, String> approvers = new HashMap<>();

    @NestedConfigurationProperty
    private ImpactWeightSettings impactWeights = new ImpactWeightSettings();

    @NestedConfigurationProperty
    private ApprovalSettings approval = new ApprovalSettings();

    @Data
    public static class AutoApproveSettings {
        private boolean enabled = false;
        private String maxImpact = "LOW";
        private double minConfidence = 0.9;
    }
    @Data
    public static class MultiApprovalSettings { private String threshold = "MEDIUM"; }
    @Data
    public static class ApproverCountSettings {
        private int criticalApprovers = 3;
        private int highApprovers = 2;
        private int mediumApprovers = 1;
        private int defaultApprovers = 1;
    }

    @Data
    public static class RejectionSettings {
        // CRITICAL impact proposals require at least this confidence to proceed
        private double criticalMinConfidence = 0.5;
        // Proposals below this confidence are rejected regardless of impact level
        private double absoluteMinConfidence = 0.1;
    }

    @Data
    public static class ApprovalSettings {
        private int expiryDays = 3;
        private int workflowTtlDays = 7;
        private String defaultEmail = "approver@contexa.com";
    }

    /**
     * Impact weight settings for governance impact reassessment.
     *
     * <p>Weight design rationale:
     * <ul>
     *   <li>Proposal type weights reflect reversibility: destructive ops (delete/revoke) get the
     *       highest weight (0.2) because they are hard to reverse. Additive ops (create/grant)
     *       get moderate weight (0.12) as they expand the attack surface. Modifications (update/optimize)
     *       get low weight (0.06) as their scope is bounded. Informational suggestions get minimal
     *       weight (0.03).</li>
     *   <li>Up-shift thresholds (0.2 / 0.3) raise impact level when aggregated score is high enough.
     *       Down-shift thresholds (0.1 / 0.05) lower impact level when evidence supports it.
     *       With default weights, theoretical max aggregate is 0.36
     *       (delete + high impact + threat response).</li>
     * </ul>
     *
     * <p>Confidence-based impact adjustment is handled exclusively in PolicyEvolutionEngine
     * to avoid double-counting. Governance uses confidence only as an auto-approve gate
     * and a rejection gate.
     *
     * <p>All values are externalized via Spring configuration for operational tuning.
     */
    @Data
    public static class ImpactWeightSettings {
        // Destructive operations (delete/revoke) are irreversible - highest weight
        private double deletePolicyWeight = 0.2;
        // Additive operations (create/grant) expand attack surface - moderate weight
        private double createPolicyWeight = 0.12;
        // Modifications (update/optimize) have bounded scope - low weight
        private double updatePolicyWeight = 0.06;
        // Informational suggestions have minimal direct security impact
        private double defaultTypeWeight = 0.03;

        // Proposals with expected impact > threshold carry broader blast radius
        private double highImpactWeight = 0.1;
        private double highImpactThreshold = 0.8;
        // Threat response proposals need urgency but carry misfire risk
        private double threatResponseWeight = 0.06;
        // Access pattern learning is incremental - minimal additional risk
        private double accessPatternWeight = 0.03;

        // Aggregated impactScore > 0.3 triggers +2 level up-shift
        private double majorUpThreshold = 0.3;
        // Aggregated impactScore > 0.2 triggers +1 level up-shift
        private double minorUpThreshold = 0.2;
        // Aggregated impactScore < 0.1 triggers -1 level down-shift
        private double minorDownThreshold = 0.1;
        // Aggregated impactScore < 0.05 triggers -2 level down-shift
        private double majorDownThreshold = 0.05;
    }
}
