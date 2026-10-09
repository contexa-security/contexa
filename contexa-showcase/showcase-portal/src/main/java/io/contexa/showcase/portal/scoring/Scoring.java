package io.contexa.showcase.portal.scoring;

import java.util.List;
import java.util.Set;

/**
 * The one scoring rule of the demo (docs/showcase/데모-재설계.md 5.0, R-08 to R-12; fabricated-data survey #11 to #13).
 * Every screen and the benchmark read their right, missed and falsely blocked from here, so no screen keeps a rule of
 * its own. Scores come only from what was recorded: the ground truth of the scenario definition the run executed, each
 * control's business outcome per step, control D's decision per step and the additional check of the step.
 * <p>
 * Two axes are kept apart. The business axis asks what happened to the data or the work in the whole case, for every
 * control. The verdict axis asks whether the engine's own decision of a step was one the ground truth allows; it exists
 * for control D only, counts a technical fallback as unresolved, never as a verdict, and says whether the decision could
 * still change the case (a decision applied from the next request has no effect after the last step).
 */
public final class Scoring {

    /** Ground truth of the scenario definition the run executed (run.scenario_definition). */
    public record Truth(String classification, List<String> allowedEngineActions) {

        public boolean threat() {
            return "THREAT".equals(classification);
        }

        public boolean normal() {
            return "NORMAL".equals(classification);
        }
    }

    /**
     * One control's answer to one step as recorded (run_arm_result, run_challenge).
     *
     * @param outcome        DELIVERED, REFUSED, NOT_FOUND, ERROR or CUT
     * @param httpStatus     the status the control answered with
     * @param deliveredItems items that left (for a cut stream, the items before the cut; for a stream that broke, the
     *                       items before it broke)
     * @param checkPassed    true when control D asked for an additional check, the run principal answered it and the
     *                       re-issued request was delivered; null when there was no check
     */
    public record StepAnswer(int stepNo, String outcome, Integer httpStatus, long deliveredItems, Boolean checkPassed) {
    }

    /**
     * Control D's decision of one step as recorded (run_decision); null fields when the engine made no decision.
     *
     * @param applied BEFORE_RESPONSE, NEXT_REQUEST or NONE
     */
    public record StepDecision(int stepNo, String finalAction, boolean unresolved, String applied) {
    }

    /** What happened to the data or the work in the whole case. */
    public enum BusinessResult {
        /** Attack: no data left at any step. */
        STOPPED,
        /** Attack: some data left before the case was stopped or cut; the exposure is kept with it. */
        PARTLY_STOPPED,
        /** Attack: the data left at every step: a miss. */
        MISSED,
        /** Legitimate work: every step delivered. */
        PASSED,
        /** Legitimate work: an additional check was answered and the work went on. */
        PASSED_AFTER_CHECK,
        /** Legitimate work: a step was refused, cut or left on hold: a false block. */
        HALTED,
        /** A request failed before any data left (no answer the case could be judged on). */
        UNRESOLVED,
        /** The scenario has no ground truth (uncertain cases, cases a visitor composed). */
        NOT_SCORED
    }

    /** Whether the engine's own decision of a step agrees with the ground truth. */
    public enum VerdictResult {
        RIGHT, MISSED, FALSE_BLOCK,
        /** The analysis did not end in a model decision (technical fallback, parser failure). */
        UNRESOLVED,
        /** The engine made no decision for the step (refused by an earlier decision, not analysed). */
        NO_DECISION,
        NOT_SCORED
    }

    /**
     * @param exposedItems items that left over the whole case
     * @param worstStep    the step that decided the result (the first that left data for an attack, the first that
     *                     halted the work for legitimate work); null when none did
     */
    public record CaseScore(BusinessResult result, long exposedItems, Integer worstStep) {
    }

    /**
     * @param applicable false when the decision could no longer change the case: applied from the next request after
     *                   the last step
     * @param friction   legitimate work met an additional check the ground truth allows
     * @param applied    when the decision applied: BEFORE_RESPONSE, NEXT_REQUEST or NONE
     */
    public record VerdictScore(int stepNo, String finalAction, VerdictResult result, boolean applicable,
                               boolean friction, String applied) {
    }

    private static final Set<String> STOPPING = Set.of("REFUSED");

    private Scoring() {
    }

    /**
     * Right, wrong, or neither: a full stop and passed work are right, a miss and halted work are wrong; a partial stop
     * (shown with its exposure), an unresolved case and a case without a ground truth are neither.
     */
    public static Boolean correct(BusinessResult result) {
        return switch (result) {
            case STOPPED, PASSED, PASSED_AFTER_CHECK -> Boolean.TRUE;
            case MISSED, HALTED -> Boolean.FALSE;
            case PARTLY_STOPPED, UNRESOLVED, NOT_SCORED -> null;
        };
    }

    /**
     * The business result of one control over the whole case. A request that ended in an error after data had left
     * (a stream that broke after its lines were sent) counts with the data that left: an error never hides an exposure.
     * Only an error before any data left makes the case unresolved.
     */
    public static CaseScore business(Truth truth, List<StepAnswer> answers) {
        long exposed = 0;
        for (StepAnswer answer : answers) {
            if (leftData(answer)) {
                exposed += answer.deliveredItems();
            }
        }
        if (!truth.threat() && !truth.normal()) {
            return new CaseScore(BusinessResult.NOT_SCORED, exposed, null);
        }
        if (answers.isEmpty() || answers.stream()
                .anyMatch(answer -> "ERROR".equals(answer.outcome()) && answer.deliveredItems() == 0)) {
            return new CaseScore(BusinessResult.UNRESOLVED, exposed, null);
        }
        return truth.threat() ? attack(answers, exposed) : legitimate(answers, exposed);
    }

    private static CaseScore attack(List<StepAnswer> answers, long exposed) {
        Integer firstLeak = null;
        boolean anyStopped = false;
        boolean anyLeak = false;
        for (StepAnswer answer : answers) {
            boolean leaked = "DELIVERED".equals(answer.outcome()) || leftData(answer) && answer.deliveredItems() > 0;
            if (leaked) {
                anyLeak = true;
                if (firstLeak == null) {
                    firstLeak = answer.stepNo();
                }
            }
            if (stopped(answer)) {
                anyStopped = true;
            }
        }
        if (!anyLeak) {
            return new CaseScore(BusinessResult.STOPPED, 0, null);
        }
        return new CaseScore(anyStopped ? BusinessResult.PARTLY_STOPPED : BusinessResult.MISSED, exposed, firstLeak);
    }

    private static CaseScore legitimate(List<StepAnswer> answers, long exposed) {
        boolean checked = false;
        for (StepAnswer answer : answers) {
            if ("DELIVERED".equals(answer.outcome())) {
                continue;
            }
            if (Boolean.TRUE.equals(answer.checkPassed())) {
                checked = true;
                continue;
            }
            return new CaseScore(BusinessResult.HALTED, exposed, answer.stepNo());
        }
        return new CaseScore(checked ? BusinessResult.PASSED_AFTER_CHECK : BusinessResult.PASSED, exposed, null);
    }

    /** Data left with the answer: delivered, or cut or broken after some lines. */
    private static boolean leftData(StepAnswer answer) {
        return "DELIVERED".equals(answer.outcome()) || "CUT".equals(answer.outcome())
                || "ERROR".equals(answer.outcome()) && answer.deliveredItems() > 0;
    }

    /** A refused request, a cut with nothing delivered, or a request not found: the data did not leave. */
    private static boolean stopped(StepAnswer answer) {
        return STOPPING.contains(answer.outcome()) || "NOT_FOUND".equals(answer.outcome())
                || "CUT".equals(answer.outcome());
    }

    /** The verdict of control D's decision of each step. */
    public static List<VerdictScore> verdicts(Truth truth, List<StepDecision> decisions, int lastStep) {
        return decisions.stream().map(decision -> verdict(truth, decision, lastStep)).toList();
    }

    static VerdictScore verdict(Truth truth, StepDecision decision, int lastStep) {
        boolean applicable = "BEFORE_RESPONSE".equals(decision.applied())
                || "NEXT_REQUEST".equals(decision.applied()) && decision.stepNo() < lastStep;
        if (decision.finalAction() == null) {
            return new VerdictScore(decision.stepNo(), null, VerdictResult.NO_DECISION, false, false,
                    decision.applied());
        }
        if (decision.unresolved()) {
            return new VerdictScore(decision.stepNo(), decision.finalAction(), VerdictResult.UNRESOLVED, applicable,
                    false, decision.applied());
        }
        if (!truth.threat() && !truth.normal()) {
            return new VerdictScore(decision.stepNo(), decision.finalAction(), VerdictResult.NOT_SCORED, applicable,
                    false, decision.applied());
        }
        boolean allowed = truth.allowedEngineActions() != null
                && truth.allowedEngineActions().contains(decision.finalAction());
        VerdictResult result = allowed ? VerdictResult.RIGHT
                : truth.threat() ? VerdictResult.MISSED : VerdictResult.FALSE_BLOCK;
        boolean friction = truth.normal() && allowed && !"ALLOW".equals(decision.finalAction());
        return new VerdictScore(decision.stepNo(), decision.finalAction(), result, applicable, friction,
                decision.applied());
    }
}
