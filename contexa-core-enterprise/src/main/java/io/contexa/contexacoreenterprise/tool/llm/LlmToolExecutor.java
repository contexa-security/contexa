package io.contexa.contexacoreenterprise.tool.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.tool.ToolCallback;

import java.util.List;


public interface LlmToolExecutor {
    
    
    String executeWithTools(Object promptSpec, 
                           List<ToolCallback> toolCallbacks,
                           List<Object> toolProviders);
    
    
    ChatResponse executeWithToolsResponse(Object promptSpec,
                                        ToolCallback[] toolCallbacks,
                                        List<Object> toolProviders);
    
    
    String executeSoarTools(Object promptSpec,
                           List<ToolCallback> soarToolCallbacks,
                           String incidentId,
                           String organizationId);
    
    
    boolean canExecuteTools(List<ToolCallback> toolCallbacks);
}