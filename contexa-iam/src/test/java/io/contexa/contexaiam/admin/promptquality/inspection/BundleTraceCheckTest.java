package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionUnavailableException;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The bundle trace check: the governance descriptor the render sealed names a release of the prompt release registry,
 * and the sealed contract version, artifact hash and approval are that release's. The sealed version is compared with
 * its own release, so a later release does not turn an earlier prompt into a mismatch. It runs on every layout.
 */
class BundleTraceCheckTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String OLD = "2026.07.30-v19";
    private static final String NEW = "2026.10.11-v19.8";
    private static final Map<String, PromptReleaseLookup.PromptRelease> REGISTRY = Map.of(
            OLD, new PromptReleaseLookup.PromptRelease(OLD, "CORTEX_PROMPT_CONTRACT_V2", "928ec415", "approval-1", "ACTIVE"),
            NEW, new PromptReleaseLookup.PromptRelease(NEW, "CORTEX_PROMPT_CONTRACT_V2", "b885cce7", "approval-2", "ACTIVE"));
    private static final PromptReleaseLookup LOOKUP = (scope, promptKey, templateKey, version) ->
            "PLATFORM_GLOBAL".equals(scope) && "cortex.security-decision".equals(promptKey)
                    && "SecurityDecisionStandard".equals(templateKey)
                    ? Optional.ofNullable(REGISTRY.get(version)) : Optional.empty();

    @Test
    void aPromptSealedUnderAnEarlierReleaseMatchesItsOwnReleaseNotTheNewest() {
        PromptInspectionCheckResult check = check(LOOKUP, descriptor(OLD, "928ec415"), "v19-sections");

        assertThat(check.checkCode()).isEqualTo("BUNDLE_TRACE");
        assertThat(check.findings()).isEmpty();
        assertThat(check.matched()).isEqualTo(10);
    }

    @Test
    void aVersionTheRegistryDoesNotHoldIsPointedAt() {
        PromptInspectionFinding finding = single(check(LOOKUP, descriptor("2026.10.12-local", "928ec415"),
                "v20-dictionary-blocks"));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.entry()).isEqualTo("promptVersion");
        assertThat(finding.actual()).isEqualTo("2026.10.12-local");
        assertThat(finding.sourceRef()).isEqualTo("promptGovernanceRegistry");
        assertThat(finding.reason()).contains("not a release");
    }

    @Test
    void anArtifactHashOtherThanTheReleasesIsPointedAt() {
        PromptInspectionFinding finding = single(check(LOOKUP, descriptor(NEW, "00000000"), "v20-dictionary-blocks"));

        assertThat(finding.entry()).isEqualTo("promptArtifactHashSha256");
        assertThat(finding.expected()).isEqualTo("b885cce7");
        assertThat(finding.actual()).isEqualTo("00000000");
    }

    @Test
    void aReleaseWithoutAnApprovalIsPointedAt() {
        PromptReleaseLookup unapproved = (scope, promptKey, templateKey, version) -> Optional.of(
                new PromptReleaseLookup.PromptRelease(NEW, "CORTEX_PROMPT_CONTRACT_V2", "b885cce7", null, "DRAFT"));

        PromptInspectionFinding finding = single(check(unapproved, descriptor(NEW, "b885cce7"), "v20-dictionary-blocks"));
        assertThat(finding.entry()).isEqualTo("releaseApprovalReference");
    }

    @Test
    void aDescriptorWithoutItsFieldsIsPointedAtFieldByField() {
        Map<String, Object> descriptor = descriptor(NEW, "b885cce7");
        descriptor.remove("templateKey");
        descriptor.remove("contractVersion");

        PromptInspectionCheckResult check = check(LOOKUP, descriptor, "v20-dictionary-blocks");
        assertThat(check.findings()).extracting(PromptInspectionFinding::entry)
                .containsExactly("templateKey", "contractVersion");
        assertThat(check.findings()).allMatch(finding -> finding.sourceRef().startsWith("executionMetadata.governanceDescriptor"));
    }

    /** R1b-5: a registry that cannot be read now is a passing outage, not a lasting error of the package. */
    @Test
    void aRegistryThatCannotBeReadNowLeavesTheInspectionForALaterRound() {
        PromptReleaseLookup down = (scope, promptKey, templateKey, version) -> {
            throw new DataAccessResourceFailureException("connection refused");
        };
        Map<String, Object> withLayout = new LinkedHashMap<>(descriptor(NEW, "b885cce7"));
        withLayout.put("userPromptLayoutVersion", "v20-dictionary-blocks");
        PromptInspector inspector = new PromptInspector(List.of(new BundleTraceCheck(down)), JSON);

        assertThatThrownBy(() -> inspector.inspect(sealed(withLayout)))
                .isInstanceOf(PromptInspectionUnavailableException.class);
    }

    @Test
    void withoutARegistryTheTraceCannotBeToldAndSaysSo() {
        PromptInspectionCheckResult check = check(null, descriptor(NEW, "b885cce7"), "v20-dictionary-blocks");

        assertThat(single(check).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(single(check).sourceRef()).isEqualTo("promptGovernanceRegistry");
    }

    private static Map<String, Object> descriptor(String version, String hash) {
        Map<String, Object> descriptor = new LinkedHashMap<>();
        descriptor.put("registryScope", "PLATFORM_GLOBAL");
        descriptor.put("promptKey", "cortex.security-decision");
        descriptor.put("templateKey", "SecurityDecisionStandard");
        descriptor.put("promptVersion", version);
        descriptor.put("contractVersion", "CORTEX_PROMPT_CONTRACT_V2");
        descriptor.put("promptArtifactHashSha256", hash);
        return descriptor;
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        assertThat(check.findings()).hasSize(1);
        return check.findings().get(0);
    }

    private static PromptInspectionCheckResult check(PromptReleaseLookup lookup, Map<String, Object> descriptor,
                                                     String layout) {
        Map<String, Object> withLayout = new LinkedHashMap<>(descriptor);
        withLayout.put("userPromptLayoutVersion", layout);
        PromptInspectionResult result = new PromptInspector(List.of(new BundleTraceCheck(lookup)), JSON)
                .inspect(sealed(withLayout));
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    private static SealedEvidencePackage sealed(Map<String, Object> descriptor) {
        try {
            return SealedEvidencePackage.builder()
                    .packageId("bundle-trace")
                    .userPromptText("=== REQUEST ===\nSubject: user-1\n")
                    .rawUserPrompt("=== REQUEST ===\nSubject: user-1\n")
                    .promptExecutionMetadataJson(JSON.writeValueAsString(Map.of("governanceDescriptor", descriptor)))
                    .build();
        }
        catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
