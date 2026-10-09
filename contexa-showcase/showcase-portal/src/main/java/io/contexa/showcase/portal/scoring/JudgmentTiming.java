package io.contexa.showcase.portal.scoring;

import io.contexa.showcase.portal.scoring.RunScores.DecisionSource;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.RunScores.StepVerdict;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;

import java.util.List;
import java.util.Optional;

/**
 * How Contexa's answer to an attack run came about (work 16 of docs/showcase/화면설계서-v2-구현계획.md), so the
 * benchmark tells a limit of timing from a limit of judgement. Read from the run's score alone: the business result
 * of control D, and per step where its answer came from, what the engine decided and when that applied.
 */
public final class JudgmentTiming {

    public enum Kind {
        /** The static authorization refused the request before any analysis. */
        STATIC_REFUSAL,
        /** The engine decided before the response and nothing left. */
        BEFORE_RESPONSE,
        /** Items left first; a decision applied from the next request refused what followed. */
        NEXT_REQUEST,
        /** Every decision of the engine was to allow, so the data left. */
        JUDGED_ALLOW,
        /** Any other shape, counted apart rather than fitted into one of the kinds above. */
        OTHER
    }

    private JudgmentTiming() {
    }

    /** The kind of control D's answer to an attack run; empty for a run that is not an attack or has no result. */
    public static Optional<Kind> of(RunScore score) {
        if (!score.truth().threat()) {
            return Optional.empty();
        }
        CaseScore business = score.business().get("D");
        if (business == null || business.result() == BusinessResult.UNRESOLVED
                || business.result() == BusinessResult.NOT_SCORED) {
            return Optional.empty();
        }
        List<StepVerdict> verdicts = score.verdicts();
        return Optional.of(switch (business.result()) {
            case STOPPED -> stopped(verdicts);
            case PARTLY_STOPPED -> partlyStopped(verdicts);
            case MISSED -> missed(verdicts);
            default -> Kind.OTHER;
        });
    }

    /** Nothing left: decided by the first step that was answered by something other than "not analysed". */
    private static Kind stopped(List<StepVerdict> verdicts) {
        for (StepVerdict verdict : verdicts) {
            if (verdict.source() == DecisionSource.NOT_ANALYSED) {
                continue;
            }
            if (verdict.source() == DecisionSource.STATIC_AUTHORIZATION) {
                return Kind.STATIC_REFUSAL;
            }
            return modelDecision(verdict) && "BEFORE_RESPONSE".equals(verdict.score().applied())
                    && !"ALLOW".equals(verdict.score().finalAction()) ? Kind.BEFORE_RESPONSE : Kind.OTHER;
        }
        return Kind.OTHER;
    }

    /** Some items left: a refusing decision applied from the next request, and a later step refused because of it. */
    private static Kind partlyStopped(List<StepVerdict> verdicts) {
        for (StepVerdict decided : verdicts) {
            if (!modelDecision(decided) || !"NEXT_REQUEST".equals(decided.score().applied())
                    || "ALLOW".equals(decided.score().finalAction())) {
                continue;
            }
            boolean refusedAfter = verdicts.stream().anyMatch(later -> later.score().stepNo() > decided.score().stepNo()
                    && later.source() == DecisionSource.PRIOR_DECISION);
            if (refusedAfter) {
                return Kind.NEXT_REQUEST;
            }
        }
        return Kind.OTHER;
    }

    /** The data left: a judgement to allow when every decision the model made was to allow. */
    private static Kind missed(List<StepVerdict> verdicts) {
        List<StepVerdict> decided = verdicts.stream().filter(verdict -> verdict.score().finalAction() != null)
                .toList();
        boolean allAllowedByModel = !decided.isEmpty() && decided.stream().allMatch(verdict ->
                modelDecision(verdict) && "ALLOW".equals(verdict.score().finalAction()));
        return allAllowedByModel ? Kind.JUDGED_ALLOW : Kind.OTHER;
    }

    /**
     * Whether the model judged an attack run risky: at least one of its decisions was not to allow. The screen's
     * sentence "every attack it judged risky was stopped" holds when every such run was stopped, fully or after some
     * items left (section 8 of the plan).
     */
    public static boolean judgedRisky(RunScore score) {
        return score.verdicts().stream().anyMatch(verdict -> modelDecision(verdict)
                && verdict.score().finalAction() != null && !"ALLOW".equals(verdict.score().finalAction()));
    }

    private static boolean modelDecision(StepVerdict verdict) {
        return verdict.source() == DecisionSource.MODEL || verdict.source() == DecisionSource.PROPOSAL_CHANGED;
    }
}
