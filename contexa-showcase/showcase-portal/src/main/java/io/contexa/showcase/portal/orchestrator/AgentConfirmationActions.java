package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ControlSession.AgentConfirmationStatus;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

import java.io.IOException;

/**
 * docs/agent A7-3: what happens to a confirmation control D asked of an agent's request (A5-2), each through the
 * engine's own endpoints: the delegating person answers it in the person's own session, the agent reads it and sends
 * the confirmed request again with it, once, and the engine refuses it on another request and a second time (A5-9).
 * docs/agent DD-27: the agent may also send the request again without it, and the person may send the same request in
 * the person's own session.
 */
public interface AgentConfirmationActions {

    /**
     * The delegating person approves, rejects or reports the request on the engine's confirmation page.
     *
     * @return the page's HTTP status (a redirect once the answer is taken)
     */
    int decide(DelegatorAnswer answer) throws IOException;

    /** The confirmation as the agent reads it through the engine's confirmation API. */
    AgentConfirmationStatus status() throws IOException;

    /** The agent sends the confirmed request again with the confirmation. */
    StepOutcome resend() throws IOException;

    /** The agent sends another request with the same confirmation. */
    StepOutcome resendOther() throws IOException;

    /** The agent sends the request again as it first did, without the confirmation. */
    StepOutcome retry() throws IOException;

    /** The delegating person sends the agent's request in the person's own session. */
    StepOutcome personRequest() throws IOException;
}
