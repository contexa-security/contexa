package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

import java.util.Map;

/** Progress of a run as it happens, for a visitor watching a live run; recordings use {@link #NONE}. */
public interface RunListener {

    RunListener NONE = new RunListener() {
    };

    /** The visitor hash of a live run, so the daily allotment counts its cost; null for recordings. */
    default String liveVisitor() {
        return null;
    }

    default void runStarted(String runId) {
    }

    /**
     * The run principal is cloned and signed in to every control: the visitor's space is ready (deck p.27).
     *
     * @param stageMs milliseconds of each preparation stage, in order: template, businessPrincipal, enginePrincipal,
     *                plainSignIn, engineSignIn
     */
    default void principalReady(Map<String, Long> stageMs) {
    }

    default void stepResult(int stepNo, String operation, Control control, StepOutcome outcome) {
    }
}
