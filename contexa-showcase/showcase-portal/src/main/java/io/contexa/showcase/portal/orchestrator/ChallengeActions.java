package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

import java.io.IOException;
import java.util.Optional;

/** What a run principal can do when control D asks for an additional check, in its own session (deck p.12). */
public interface ChallengeActions {

    /** Asks control D to send a one-time code; returns the HTTP status (200 or 302 when sent). */
    int requestCode() throws IOException;

    /** The code the demo inbox received; taking it empties the inbox, so it is always the newest code. */
    Optional<String> readCode() throws IOException;

    /** Submits a code; returns the HTTP status (200 when verified). */
    int submitCode(String code) throws IOException;

    /** Sends the original request again in the same session. */
    StepOutcome reissue() throws IOException;
}
