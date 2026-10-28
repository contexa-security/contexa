package io.contexa.showcase.portal.agent;

import java.time.Duration;

/**
 * docs/agent A7-2b: what runs the business agent of an agent task, and the limits of a task that names none.
 *
 * @param maxToolCalls the most tool calls a task may make
 * @param maxTime      the longest a task may take
 * @param liveLimits   the hard limits of a visitor's live run (docs/agent Agent중심-화면 AC-3); null for none
 */
public record AgentTasks(BusinessAgent agent, AgentModels models, int maxToolCalls, Duration maxTime,
                         AgentRunCap.Limits liveLimits) {

    public AgentTasks(BusinessAgent agent, AgentModels models, int maxToolCalls, Duration maxTime) {
        this(agent, models, maxToolCalls, maxTime, null);
    }
}
