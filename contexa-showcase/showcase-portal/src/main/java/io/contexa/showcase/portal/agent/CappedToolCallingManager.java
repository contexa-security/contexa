package io.contexa.showcase.portal.agent;

import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.model.tool.ToolExecutionResult;
import org.springframework.ai.tool.definition.ToolDefinition;

import java.util.List;

/**
 * docs/agent Agent중심-화면 AC-3: the tool step of the agent's model loop, which tells the live run's cap how many input
 * tokens the model has used so far, before the tools of that round run. Spring AI passes this step the response of the
 * round with the usage summed over the rounds before it (OpenAI and Anthropic alike), so the count is the model's own.
 * Without a cap bound to the thread the step does nothing but pass on.
 */
public final class CappedToolCallingManager implements ToolCallingManager {

    private final ToolCallingManager delegate;

    public CappedToolCallingManager(ToolCallingManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<ToolDefinition> resolveToolDefinitions(ToolCallingChatOptions chatOptions) {
        return delegate.resolveToolDefinitions(chatOptions);
    }

    @Override
    public ToolExecutionResult executeToolCalls(Prompt prompt, ChatResponse chatResponse) {
        AgentRunCap cap = AgentRunCap.current();
        if (cap != null && chatResponse != null && chatResponse.getMetadata() != null) {
            Integer inputTokens = AgentUsage.promptTokens(chatResponse.getMetadata().getUsage());
            if (inputTokens != null) {
                cap.inputTokens(inputTokens);
            }
        }
        return delegate.executeToolCalls(prompt, chatResponse);
    }
}
