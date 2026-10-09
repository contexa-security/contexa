package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

import java.io.IOException;
import java.util.Optional;

/**
 * What a run principal whose account control D blocked can do to ask for the release, in its own session and through
 * the engine's own endpoints (ADR-33): start the identity check of the blocked account, pass it with the e-mailed
 * one-time code, ask the administrators for the release with a reason, and send the original request again.
 */
public interface ReleaseActions {

    /** Starts the identity check of the blocked account; returns the HTTP status (200 when started). */
    int startCheck() throws IOException;

    /**
     * Sends an ordinary request, which the engine answers by starting the check of the blocked account, then asks for
     * the one-time code; returns the HTTP status of the code request (200 or 302 when sent).
     */
    int requestCode() throws IOException;

    /** The code the demo inbox received; taking it empties the inbox, so it is always the newest code. */
    Optional<String> readCode() throws IOException;

    /** Submits a code; returns the HTTP status (200 when verified). */
    int submitCode(String code) throws IOException;

    /** Asks the administrators for the release with a reason; returns the HTTP status (200 when filed). */
    int requestRelease(String reason) throws IOException;

    /** Sends the original request again in the same session. */
    StepOutcome reissue() throws IOException;
}
