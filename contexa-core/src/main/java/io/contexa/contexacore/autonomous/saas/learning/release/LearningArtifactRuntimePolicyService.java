package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates common runtime policy for learning artifacts.
 */
@Service
public class LearningArtifactRuntimePolicyService {

    public LearningArtifactRuntimePolicyDecision evaluate(
            LearningArtifactMetadata metadata,
            boolean tenantOptIn,
            boolean tenantKillSwitchActive) {
        LearningArtifactMetadata current = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
        LearningArtifactReleaseState releaseState = current.releaseState();
        List<String> facts = new ArrayList<>();
        facts.add("releaseState=" + releaseState.name());
        facts.add("tenantOptIn=" + tenantOptIn);
        facts.add("tenantKillSwitchActive=" + tenantKillSwitchActive);

        if (tenantKillSwitchActive || releaseState == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE) {
            facts.add("Runtime policy blocks deployment because kill switch is active.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    tenantOptIn,
                    true,
                    false,
                    false,
                    releaseState == LearningArtifactReleaseState.WITHDRAWN,
                    "KILL_SWITCH_ACTIVE",
                    "WITHDRAW",
                    facts);
        }

        if (releaseState == LearningArtifactReleaseState.WITHDRAWN) {
            facts.add("Runtime policy withdraws the artifact because release state is WITHDRAWN.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    tenantOptIn,
                    false,
                    false,
                    false,
                    true,
                    "WITHDRAWN",
                    "WITHDRAW",
                    facts);
        }

        if (releaseState == LearningArtifactReleaseState.REVIEW_ONLY) {
            facts.add("Runtime policy keeps the artifact in review-only mode.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    tenantOptIn,
                    false,
                    false,
                    true,
                    false,
                    "REVIEW_ONLY",
                    "WITHHOLD",
                    facts);
        }

        if (releaseState == LearningArtifactReleaseState.PROMOTED) {
            if (!tenantOptIn) {
                facts.add("Runtime policy requires tenant opt-in before promoted artifacts can be enabled.");
                return new LearningArtifactRuntimePolicyDecision(
                        releaseState,
                        false,
                        false,
                        false,
                        false,
                        false,
                        "TENANT_OPT_IN_REQUIRED",
                        "WITHHOLD",
                        facts);
            }
            facts.add("Runtime policy allows the promoted artifact because tenant opt-in is active.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    true,
                    false,
                    true,
                    false,
                    false,
                    "READY",
                    "ALLOW_RUNTIME",
                    facts);
        }

        facts.add("Runtime policy withholds the artifact until the release lifecycle reaches PROMOTED.");
        return new LearningArtifactRuntimePolicyDecision(
                releaseState,
                tenantOptIn,
                false,
                false,
                false,
                false,
                releaseState.name(),
                "WITHHOLD",
                facts);
    }
}
