package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.ControlSession.RetryStorm;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * docs/agent DD-27 (A6-C23, A5-7): an agent that ignores the confirmation its request waits for and sends the request
 * again and again at once. Control D answers each at its gate without calling a decision model, so the run shows its
 * call limit deterministically: past the limit the answer is 429 with the seconds to wait, and once the agent waited
 * them it is let through to the gate again.
 */
final class AgentRetryStorm {

    /** The call limit's answer (contexa-identity {@code AgentConfirmationGate.CALL_LIMIT}). */
    static final String CALL_LIMIT = "AGENT_CALL_LIMIT";

    /** Waits a call limit answer asks for, when no answer says how long. */
    static final long DEFAULT_WAIT_SECONDS = 60;

    private static final ObjectMapper JSON = new ObjectMapper();

    private AgentRetryStorm() {
    }

    /** How the agent waits; a test does not. */
    @FunctionalInterface
    interface Pause {

        Pause SLEEP = seconds -> Thread.sleep(seconds * 1000);

        void seconds(long seconds) throws InterruptedException;
    }

    static RetryStorm run(AgentConfirmationActions actions, int times, Pause pause)
            throws IOException, InterruptedException {
        Map<String, Integer> outcomes = new LinkedHashMap<>();
        Integer firstLimitedAt = null;
        StepOutcome firstLimited = null;
        StepOutcome lastLimited = null;
        for (int sent = 1; sent <= times; sent++) {
            StepOutcome outcome = actions.retry();
            outcomes.merge(outcome.httpStatus() + " " + outcome.ruleId(), 1, Integer::sum);
            if (limited(outcome)) {
                if (firstLimited == null) {
                    firstLimitedAt = sent;
                    firstLimited = outcome;
                }
                lastLimited = outcome;
            }
        }
        if (lastLimited == null) {
            return new RetryStorm(times, outcomes, null, null, null, null);
        }
        // One second over the wait, so the request is not sent at the very second the window turns.
        long waited = retryAfterSeconds(lastLimited) + 1;
        pause.seconds(waited);
        return new RetryStorm(times, outcomes, firstLimitedAt, firstLimited, waited, actions.retry());
    }

    static boolean limited(StepOutcome outcome) {
        return outcome.httpStatus() != null && outcome.httpStatus() == 429 && CALL_LIMIT.equals(outcome.ruleId());
    }

    /** The seconds the call limit answer asks the agent to wait (its {@code retryAfterSeconds}). */
    static long retryAfterSeconds(StepOutcome outcome) {
        if (outcome.excerpt() == null) {
            return DEFAULT_WAIT_SECONDS;
        }
        try {
            JsonNode found = JSON.readTree(outcome.excerpt()).findValue("retryAfterSeconds");
            return found != null && found.canConvertToLong() && found.asLong() > 0 ? found.asLong()
                    : DEFAULT_WAIT_SECONDS;
        } catch (IOException e) {
            return DEFAULT_WAIT_SECONDS;
        }
    }
}
