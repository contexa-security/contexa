package io.contexa.showcase.portal.agent;

import io.contexa.showcase.business.work.BusinessOperation;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** docs/agent A7-2b: what a business agent's work is made of and what it leaves behind. */
public final class AgentWork {

    private AgentWork() {
    }

    /**
     * One business request of the agent's work, as its tool asks for it: the operation and its target. Which of the
     * fields an operation uses is the operation's own (a document key for a read, a project and items for an export).
     * {@code claimedTicket} (docs/agent A6-C14) is the ticket an export says it is for, and {@code destination}
     * (docs/agent A6-R9) where an export says its documents go, both as the agent wrote them.
     */
    public record Request(BusinessOperation operation, String project, String document, String customer,
                          Integer items, String type, String query, String grantee, String responsibility,
                          String claimedTicket, String destination) {

        public Request(BusinessOperation operation, String project, String document, String customer, Integer items,
                       String type, String query, String grantee, String responsibility, String claimedTicket) {
            this(operation, project, document, customer, items, type, query, grantee, responsibility, claimedTicket,
                    null);
        }

        public Request(BusinessOperation operation, String project, String document, String customer, Integer items,
                       String type, String query, String grantee, String responsibility) {
            this(operation, project, document, customer, items, type, query, grantee, responsibility, null, null);
        }
    }

    /**
     * What every control answered to one request of the work: control D's answer as the agent receives it, and the
     * outcome at each control.
     *
     * @param controls the outcome at each control (DELIVERED, REFUSED, ...)
     * @param items    the items each control delivered
     */
    public record Answer(int stepNo, String path, int httpStatus, String outcome, String rule, String body,
                         Map<String, String> controls, Map<String, Integer> items, Map<String, String> excerpts) {
    }

    /** Sends one request of the work to every control at once; the agent gets control D's answer. */
    @FunctionalInterface
    public interface Sender {
        Answer send(Request request) throws IOException;
    }

    /**
     * One tool call of the work as it was made and answered.
     *
     * @param arguments what the agent passed
     * @param result    the text the agent received
     * @param sent      whether a request went to the controls (a call past the budget sends nothing)
     */
    public record ToolCall(int number, String tool, Map<String, Object> arguments, Instant at, boolean sent,
                           Answer answer, String result) {
    }

    /**
     * The agent's work from instruction to answer.
     *
     * @param stopReason ANSWERED, TOOL_BUDGET (it answered after its budget ran out), TIME_LIMIT or FAILED
     * @param usage      the model's token counts of the whole work, summed over its tool-call rounds (Spring AI's
     *                   cumulative usage)
     */
    public record Transcript(String model, String systemPrompt, String instruction, List<ToolCall> toolCalls,
                             String finalAnswer, String stopReason, String failure, Map<String, Integer> usage,
                             Instant startedAt, Instant finishedAt) {
    }
}
