package io.contexa.showcase.portal.orchestrator;

/**
 * docs/agent A7-3, DD-27: what the delegating person does with a confirmation control D asked of an agent's request.
 * A visitor approves or rejects; an operator's check may also report the agent (the engine blocks and stops it, A5-2
 * and A5-3) or leave the confirmation unanswered while the agent keeps sending the request (A5-7).
 */
public enum DelegatorAnswer {

    APPROVE("/approve"),
    REJECT("/reject"),
    REPORT("/report"),
    SILENT(null);

    private final String pagePath;

    DelegatorAnswer(String pagePath) {
        this.pagePath = pagePath;
    }

    /** The engine's confirmation page action this answer posts to; none for an answer that is not given. */
    public String pagePath() {
        if (pagePath == null) {
            throw new IllegalStateException(this + " is no answer on the confirmation page");
        }
        return pagePath;
    }
}
