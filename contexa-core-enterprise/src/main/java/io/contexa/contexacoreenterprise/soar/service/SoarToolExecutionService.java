package io.contexa.contexacoreenterprise.soar.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalAwareToolCallingManagerDecorator;
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
    private final ApprovalAwareToolCallingManagerDecorator approvalManager;

    public Mono<String> executeWithHumanApproval(String userPrompt, String incidentId, String organizationId) {

        ToolCallback[] soarToolCallbacks = getSoarToolCallbacks();

        String enhancedPrompt = enhancePromptWithSoarContext(userPrompt, incidentId, organizationId);
        Prompt prompt = new Prompt(enhancedPrompt);

        // Set SOAR context for approval-aware tool execution
        SoarContext soarContext = new SoarContext();
        soarContext.setIncidentId(incidentId);
        soarContext.setOrganizationId(organizationId);
        soarContext.setRequiresApproval(true);
        approvalManager.setCurrentContext(soarContext);

        return toolCapableLLMClient.callToolCallbacks(prompt, soarToolCallbacks)
                .doOnSuccess(result -> {
                        approvalManager.clearCurrentContext();
                        log.error("SOAR tool execution completed - incident: {}", incidentId);
                })
                .doOnError(error -> {
                        approvalManager.clearCurrentContext();
                        log.error("SOAR tool execution failed - incident: {}", incidentId, error);
                });
    }

    public Flux<String> streamWithHumanApproval(String userPrompt, String incidentId, String organizationId) {

        ToolCallback[] soarToolCallbacks = getSoarToolCallbacks();
        String enhancedPrompt = enhancePromptWithSoarContext(userPrompt, incidentId, organizationId);
        Prompt prompt = new Prompt(enhancedPrompt);

        // Set SOAR context for approval-aware tool execution
        SoarContext soarContext = new SoarContext();
        soarContext.setIncidentId(incidentId);
        soarContext.setOrganizationId(organizationId);
        soarContext.setRequiresApproval(true);
        approvalManager.setCurrentContext(soarContext);

        return toolCapableLLMClient.streamToolCallbacks(prompt, soarToolCallbacks)
                .doOnComplete(() -> {
                        approvalManager.clearCurrentContext();
                        log.error("SOAR tool stream completed - incident: {}", incidentId);
                })
                .doOnError(error -> {
                        approvalManager.clearCurrentContext();
                        log.error("SOAR tool stream failed - incident: {}", incidentId, error);
                });
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
        // Restrict direct execution to read-only/monitoring tools only
        if (!isReadOnlyTool(toolName)) {
            log.error("Unauthorized direct tool execution blocked: {}", toolName);
            throw new SecurityException("Direct execution not allowed for tool: " + toolName);
        }

        ToolCallback toolCallback = toolResolver.resolve(toolName);
        if (toolCallback == null) {
            throw new IllegalArgumentException("Tool not found: " + toolName);
        }

        try {
            return toolCallback.call(toolInput);
        } catch (Exception e) {
            log.error("Tool execution failed: {}", toolName, e);
            throw new RuntimeException("Tool execution failed: " + e.getMessage(), e);
        }
    }

    private boolean isReadOnlyTool(String toolName) {
        if (toolName == null) {
            return false;
        }
        String lower = toolName.toLowerCase();
        return lower.startsWith("query") || lower.startsWith("get")
                || lower.startsWith("list") || lower.startsWith("search")
                || lower.startsWith("check") || lower.startsWith("view")
                || lower.contains("monitor") || lower.contains("status");
    }
}