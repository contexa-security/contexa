package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;

import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * W7-14: the version screens' lists and defaults, kept in one place for the page controller, the API and the screen
 * scripts: the canonical states (decision 1, PV-14), which a transition is also requested by (N-GOV-4), the
 * transitions the screens offer as buttons, the gate blocker and rollback refusal codes they name, and the default
 * period of the behaviour comparison.
 */
public final class PromptReleaseScreen {

    /** The canonical states in lifecycle order; the screens name a state by no other word (PV-14). */
    public static final List<String> STATES = Arrays.stream(PromptBundleState.values()).map(Enum::name).toList();

    /** The transitions the screens offer as buttons (plan W7-14): the shadow, canary and active releases. */
    public static final List<String> ACTIONS = List.of(PromptBundleState.SHADOW.name(),
            PromptBundleState.CANARY.name(), PromptBundleState.ACTIVE.name());

    /** The codes a release gate blocker starts with (PromptGovernanceReleaseGateService.determineBlockers). */
    public static final List<String> BLOCKERS = List.of("ILLEGAL_STATE_TRANSITION", "EVALUATION_NOT_FOR_BUNDLE_HASH",
            "CHANGE_LEDGER_MISSING", "MODEL_COMPATIBILITY_MISSING", "BUDGET_PROFILE_MISSING", "ROLLBACK_TARGET_MISSING",
            "PROMPT_INJECTION_GATE_FAILED", "NON_FUNCTIONAL_GATE_FAILED", "EMPIRICAL_EVAL_MISSING",
            "TEVV_GATE_NOT_READY", "TOKEN_COUNTING_POLICY_MISSING", "CACHE_POLICY_MISSING",
            "COMPACTION_POLICY_MISSING",
            // N-GOV-5: a deprecation needs another active release in the bundle's place.
            "NO_OTHER_ACTIVE_RELEASE");

    /** The reasons a rollback or its approval is refused (PromptBundleRollbackService). */
    public static final List<String> REFUSALS = List.of("SOURCE_NOT_EXECUTING", "TARGET_NOT_IN_BUILD",
            "TARGET_NOT_DECLARED", "VOCABULARY_INCOMPATIBLE", "TARGET_NOT_REGISTERED", "POLICY_SET_MISSING",
            "EXECUTION_NOT_FOUND", "NOT_AWAITING_APPROVAL", "APPROVER_IS_ACTOR");

    /** The statuses a recorded rollback execution can have. */
    public static final List<String> EXECUTIONS = List.of(PromptBundleRollbackService.EXECUTED,
            PromptBundleRollbackService.AWAITING_APPROVAL, PromptBundleRollbackService.APPROVED,
            PromptBundleRollbackService.REFUSED);

    /** The two stages a sealed decision is recorded at: the applied decision and a shadow run (W6-9). */
    public static final List<String> STAGES = List.of(JdbcPromptInspectionQueries.DECISION_STAGE,
            JdbcPromptInspectionQueries.SHADOW_STAGE);

    /** The tone of each state's chip, in the chip tones of the inspection screens: enforced green, a canary amber. */
    public static final Map<String, String> TONES = Map.of(PromptBundleState.AVAILABLE.name(), "neutral",
            PromptBundleState.SHADOW.name(), "neutral", PromptBundleState.CANARY.name(), "unverifiable",
            PromptBundleState.ACTIVE.name(), "matched", PromptBundleState.DEPRECATED.name(), "neutral",
            PromptBundleState.RETIRED.name(), "neutral");

    /** The capture period the behaviour comparison reads when none is given. */
    public static final Duration DEFAULT_PERIOD = Duration.ofDays(7);

    private PromptReleaseScreen() {
    }

    /**
     * What the screen scripts take from here, as one object. A transition is requested by its canonical state, which
     * the transition API reads (N-GOV-4).
     */
    static Map<String, Object> scriptSettings() {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("states", STATES);
        settings.put("tones", TONES);
        settings.put("actions", ACTIONS);
        settings.put("blockers", BLOCKERS);
        settings.put("refusals", REFUSALS);
        settings.put("activeState", PromptBundleState.ACTIVE.name());
        settings.put("awaitingApproval", PromptBundleRollbackService.AWAITING_APPROVAL);
        settings.put("refused", PromptBundleRollbackService.REFUSED);
        settings.put("defaultScope", PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE);
        settings.put("periodDays", DEFAULT_PERIOD.toDays());
        return settings;
    }
}
