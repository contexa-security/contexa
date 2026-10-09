package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

import java.time.Instant;
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

    /** A control's request of a step went out; the engine's analysis of it can be read by this request ID. */
    default void requestSent(int stepNo, Control control, BusinessOperation operation, String requestId,
                             Instant sentAt) {
    }

    /**
     * How far a control's streamed export got while it is still being read.
     *
     * @param total items the export announced, or null when the response did not say
     * @param atMs  milliseconds since the request was sent
     */
    default void streamProgress(int stepNo, Control control, Integer total, long atMs, int delivered) {
    }

    /**
     * A step the visitor sends is next: a live run waits for the visitor's press. Recordings send it at once.
     *
     * @return true to send the step, false to end the run without it and the steps after it
     */
    default boolean awaitVisitor(int stepNo) {
        return true;
    }
}
