package io.contexa.showcase.portal.agent;

/**
 * docs/agent Agent중심-화면 AC-3: the hard limits of one visitor's live agent run. A run that reaches one stops sending
 * (the agent is told to give its final answer) and is recorded with the stop reason {@code CAP_*}; the result screen
 * closes it as "so far". The operator's measurement path has no cap, so what is measured does not change.
 * <p>
 * The input tokens are the model's own count: Spring AI hands the tool step the usage summed over the rounds so far,
 * so the limit is checked after each round (the round that answers comes after it and is not cut). The decisions are
 * the requests the run sent to the controls, counted by the run, for the agent and for the workers beside it.
 */
public final class AgentRunCap {

    public static final String TOOL_CALLS = "CAP_TOOL_CALLS";
    public static final String DECISIONS = "CAP_DECISIONS";
    public static final String INPUT_TOKENS = "CAP_INPUT_TOKENS";

    /**
     * @param toolCalls   the most tool calls of the run; a case cannot raise it, only lower it
     * @param decisions   the most requests of the run decided by the controls, the person's included
     * @param inputTokens the most input tokens of the agent's model over the run
     */
    public record Limits(int toolCalls, int decisions, int inputTokens) {

        public static Limits defaults() {
            return new Limits(12, 20, 40_000);
        }
    }

    /** The cap of the run whose agent works on this thread; the tool step of Spring AI has no other way to see it. */
    private static final ThreadLocal<AgentRunCap> CURRENT = new ThreadLocal<>();

    private final Limits limits;
    private volatile String reached;

    public AgentRunCap(Limits limits) {
        this.limits = limits;
    }

    public Limits limits() {
        return limits;
    }

    /** The first limit the run reached, or null. */
    public String reached() {
        return reached;
    }

    /** Whether the run may have another request decided; reaching the limit is recorded. */
    public boolean admitDecision(int decisionsSoFar) {
        if (decisionsSoFar >= limits.decisions()) {
            reach(DECISIONS);
            return false;
        }
        return true;
    }

    /** The input tokens of the model so far, summed over the rounds. */
    public void inputTokens(int sumSoFar) {
        if (sumSoFar > limits.inputTokens()) {
            reach(INPUT_TOKENS);
        }
    }

    synchronized void reach(String reason) {
        if (reached == null) {
            reached = reason;
        }
    }

    /** Binds the run's cap to the thread its agent works on; null unbinds. */
    static void bind(AgentRunCap cap) {
        if (cap == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(cap);
        }
    }

    static AgentRunCap current() {
        return CURRENT.get();
    }
}
