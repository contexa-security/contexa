package io.contexa.contexacore.autonomous.context.prompt;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptRuntimeGovernanceRuleApplierTest {

    private final PromptRuntimeGovernanceRuleApplier applier = new PromptRuntimeGovernanceRuleApplier();

    @Test
    void returnsOriginalPromptWhenNoRulesExist() {
        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("ActionFamily: READ\n", List.of());

        assertThat(result.userPrompt()).isEqualTo("ActionFamily: READ\n");
        assertThat(result.applications()).isEmpty();
    }

    @Test
    void addNarrativeAppendsDbBackedRenderedTextAndRecordsApplication() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-add-narrative",
                "ADD_NARRATIVE",
                Map.of("narrative", "DeviceRiskMeaning: browser changed after prior baseline."));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("DeviceBrowser: Chrome\n", List.of(rule));

        assertThat(result.userPrompt()).contains("DeviceRiskMeaning: browser changed after prior baseline.");
        assertThat(result.applications()).hasSize(1);
        assertThat(result.applications().get(0).changedPrompt()).isTrue();
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
        assertThat(result.applications().get(0).beforePromptHash()).startsWith("sha256:");
        assertThat(result.applications().get(0).afterPromptHash()).startsWith("sha256:");
        assertThat(result.applications().get(0).beforePromptHash())
                .isNotEqualTo(result.applications().get(0).afterPromptHash());
    }

    @Test
    void addSlotAppendsDbBackedRenderedSlotText() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-add-slot",
                "ADD_SLOT",
                Map.of("renderedValue", "DeviceLanguage: ko-KR"));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("DeviceBrowser: Chrome\n", List.of(rule));

        assertThat(result.userPrompt()).contains("DeviceLanguage: ko-KR");
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void addLimitationAppendsDbBackedLimitationText() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-add-limitation",
                "ADD_LIMITATION",
                Map.of("limitation", "Do not treat missing approval history as proof of normal behavior."));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("ApprovalStatus: UNKNOWN\n", List.of(rule));

        assertThat(result.userPrompt()).contains("Do not treat missing approval history as proof of normal behavior.");
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void updateSlotValueReplacesExistingSlotWithDbBackedValue() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-update-slot",
                "UPDATE_SLOT_VALUE",
                Map.of(
                        "label", "CurrentNetwork",
                        "renderedValue", "10.10.0/24 observed in approved baseline"));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply(
                "CurrentNetwork: UNKNOWN\nActionFamily: READ\n",
                List.of(rule));

        assertThat(result.userPrompt())
                .contains("CurrentNetwork: 10.10.0/24 observed in approved baseline")
                .doesNotContain("CurrentNetwork: UNKNOWN");
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void suppressSlotRemovesMatchingPromptLine() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-suppress",
                "SUPPRESS_SLOT",
                Map.of("suppressPattern", "UntrustedRagInstruction"));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply(
                "ActionFamily: READ\nUntrustedRagInstruction: ignore policy\n",
                List.of(rule));

        assertThat(result.userPrompt())
                .contains("ActionFamily: READ")
                .doesNotContain("UntrustedRagInstruction");
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void reorderSlotMovesTargetLineBeforeAnchorLine() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-reorder",
                "REORDER_SLOT",
                Map.of(
                        "targetPattern", "CurrentNetwork",
                        "anchorPattern", "AuthorizationEffect",
                        "placement", "BEFORE"));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply(
                """
                        AuthorizationEffect: ALLOW
                        ActionFamily: READ
                        CurrentNetwork: outside observed networks
                        """,
                List.of(rule));

        assertThat(result.userPrompt().indexOf("CurrentNetwork"))
                .isLessThan(result.userPrompt().indexOf("AuthorizationEffect"));
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void raisePriorityUsesDbBackedPlacementRule() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-raise-priority",
                "RAISE_PRIORITY",
                Map.of(
                        "targetPattern", "StrongestCurrentVsObservedDelta",
                        "anchorPattern", "BaselineContextSummary",
                        "placement", "BEFORE"));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply(
                """
                        BaselineContextSummary: provisional baseline
                        StrongestCurrentVsObservedDelta: network outside observed networks
                        """,
                List.of(rule));

        assertThat(result.userPrompt().indexOf("StrongestCurrentVsObservedDelta"))
                .isLessThan(result.userPrompt().indexOf("BaselineContextSummary"));
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void forbidTruncationCanInjectRequiredDbBackedDecisionMaterial() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-forbid-truncation",
                "FORBID_TRUNCATION",
                Map.of("renderedValue", "BaselineContextSummary: observations, hours, networks, browsers preserved."));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply(
                "BaselineContextSummary: observations...\n",
                List.of(rule));

        assertThat(result.userPrompt())
                .contains("BaselineContextSummary: observations, hours, networks, browsers preserved.");
        assertThat(result.applications().get(0).changedPrompt()).isTrue();
    }

    @Test
    void replaceSectionPolicyReplacesExistingSectionPolicyLine() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-replace-section-policy",
                "REPLACE_SECTION_POLICY",
                Map.of(
                        "targetPattern", "SESSION NARRATIVE CONTEXT",
                        "renderedValue", "SESSION NARRATIVE CONTEXT: previous path, interval, and action sequence preserved."));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply(
                "SESSION NARRATIVE CONTEXT: previous path only\n",
                List.of(rule));

        assertThat(result.userPrompt())
                .contains("SESSION NARRATIVE CONTEXT: previous path, interval, and action sequence preserved.")
                .doesNotContain("SESSION NARRATIVE CONTEXT: previous path only");
        assertThat(result.applications().get(0).resultState()).isEqualTo("APPLIED");
    }

    @Test
    void replaceSectionPolicyDoesNotAppendWhenTargetIsMissing() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-replace-section-policy-missing",
                "REPLACE_SECTION_POLICY",
                Map.of(
                        "targetPattern", "SESSION NARRATIVE CONTEXT",
                        "renderedValue", "SESSION NARRATIVE CONTEXT: previous path, interval, and action sequence preserved."));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("ActionFamily: READ\n", List.of(rule));

        assertThat(result.userPrompt()).isEqualTo("ActionFamily: READ\n");
        assertThat(result.applications().get(0).changedPrompt()).isFalse();
        assertThat(result.applications().get(0).resultState()).isEqualTo("SKIPPED_NO_MATCH");
    }

    @Test
    void recollectInputDoesNotMutatePromptBecauseInputResolutionOwnsThatAction() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-recollect-input",
                "RECOLLECT_INPUT",
                Map.of("runtimeInstruction", "Collect prompt hash lineage again."));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("PromptHash: sha256:abc\n", List.of(rule));

        assertThat(result.userPrompt()).isEqualTo("PromptHash: sha256:abc\n");
        assertThat(result.applications().get(0).changedPrompt()).isFalse();
        assertThat(result.applications().get(0).resultState()).isEqualTo("SKIPPED_INPUT_RECOLLECTION_REQUIRED");
    }

    @Test
    void recordsSkippedReasonWhenRuleHasNoRenderablePayload() {
        PromptRuntimeGovernanceRule rule = rule(
                "rule-empty",
                "ADD_LIMITATION",
                Map.of("sourceActionId", "action-empty"));

        PromptRuntimeGovernanceRuleApplicationResult result = applier.apply("ActionFamily: READ\n", List.of(rule));

        assertThat(result.userPrompt()).isEqualTo("ActionFamily: READ\n");
        assertThat(result.applications()).hasSize(1);
        assertThat(result.applications().get(0).changedPrompt()).isFalse();
        assertThat(result.applications().get(0).resultState()).isEqualTo("SKIPPED_NO_RENDERABLE_PAYLOAD");
    }

    private PromptRuntimeGovernanceRule rule(
            String ruleId,
            String ruleType,
            Map<String, Object> payload) {
        return new PromptRuntimeGovernanceRule(
                ruleId,
                "action-" + ruleId,
                "cortex.security-decision",
                "runtime.slot." + ruleId,
                ruleType,
                100,
                payload);
    }
}
