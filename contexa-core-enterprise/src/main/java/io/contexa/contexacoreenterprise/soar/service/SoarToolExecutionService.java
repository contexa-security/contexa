package io.contexa.contexacoreenterprise.soar.service;

import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class SoarToolExecutionService {
    
    private final ToolCapableLLMClient toolCapableLLMClient;
    private final ChainedToolResolver toolResolver;

    public Mono<String> executeWithHumanApproval(String userPrompt, String incidentId, String organizationId) {

        ToolCallback[] soarToolCallbacks = getSoarToolCallbacks();

        String enhancedPrompt = enhancePromptWithSoarContext(userPrompt, incidentId, organizationId);
        Prompt prompt = new Prompt(enhancedPrompt);

        return toolCapableLLMClient.callToolCallbacks(prompt, soarToolCallbacks)
                .doOnSuccess(result ->
                        log.info("SOAR Tool 실행 완료 - 인시던트: {}", incidentId))
                .doOnError(error ->
                        log.error("SOAR Tool 실행 실패 - 인시던트: {}", incidentId, error));
    }

    public Flux<String> streamWithHumanApproval(String userPrompt, String incidentId, String organizationId) {
                
        ToolCallback[] soarToolCallbacks = getSoarToolCallbacks();
        String enhancedPrompt = enhancePromptWithSoarContext(userPrompt, incidentId, organizationId);
        Prompt prompt = new Prompt(enhancedPrompt);

        return toolCapableLLMClient.streamToolCallbacks(prompt, soarToolCallbacks)
                .doOnComplete(() ->
                        log.info("SOAR Tool 스트림 완료 - 인시던트: {}", incidentId))
                .doOnError(error ->
                        log.error("SOAR Tool 스트림 실패 - 인시던트: {}", incidentId, error));
    }

    private ToolCallback[] getSoarToolCallbacks() {
        return toolResolver.getAllToolCallbacks();
    }

    private String enhancePromptWithSoarContext(String originalPrompt, String incidentId, String organizationId) {
        StringBuilder enhanced = new StringBuilder();
        enhanced.append("SOAR (Security Orchestration, Automation and Response) Context:\n");
        enhanced.append("- Incident ID: ").append(incidentId).append("\n");
        enhanced.append("- Organization: ").append(organizationId).append("\n");
        enhanced.append("- Security Tool Execution: Human-in-the-Loop enabled\n");
        enhanced.append("- High-risk tools require manual approval\n");
        enhanced.append("- Analysis and monitoring tools execute automatically\n");
        enhanced.append("- All tool executions are logged and audited\n\n");
        enhanced.append("Security Analyst Request: ").append(originalPrompt);
        
        return enhanced.toString();
    }

    public java.util.Set<String> getRegisteredTools() {
        return toolResolver.getRegisteredToolNames();
    }

    public Map<String, Object> getExecutionStatistics() {
        return toolResolver.getToolStatistics();
    }

    public String executeToolDirectly(String toolName, String toolInput) {
                
        ToolCallback toolCallback = toolResolver.resolve(toolName);
        if (toolCallback == null) {
            throw new IllegalArgumentException("도구를 찾을 수 없습니다: " + toolName);
        }
        
        try {
            String result = toolCallback.call(toolInput);
                        return result;
        } catch (Exception e) {
            log.error("도구 실행 실패: {}", toolName, e);
            throw new RuntimeException("도구 실행 실패: " + e.getMessage(), e);
        }
    }
}