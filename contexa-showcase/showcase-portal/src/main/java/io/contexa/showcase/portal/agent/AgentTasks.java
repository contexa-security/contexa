package io.contexa.showcase.portal.agent;

import java.time.Duration;

/**
 * docs/agent A7-2b: what runs the business agent of an agent task, and the limits of a task that names none.
 *
 * @param maxToolCalls the most tool calls a task may make
 * @param maxTime      the longest a task may take
 */
public record AgentTasks(BusinessAgent agent, AgentModels models, int maxToolCalls, Duration maxTime) {
}
