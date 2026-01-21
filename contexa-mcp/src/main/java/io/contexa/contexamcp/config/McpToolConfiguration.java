package io.contexa.contexamcp.config;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.contexa.contexamcp.completions.SecurityCommandCompletion;
import io.contexa.contexamcp.prompts.SecurityAnalysisPrompts;
import io.contexa.contexamcp.resources.SecurityLogResource;
import io.contexa.contexamcp.resources.SystemInfoResource;
import io.contexa.contexamcp.tools.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "spring.ai.mcp.server", name = "enabled", havingValue = "true", matchIfMissing = true)
public class McpToolConfiguration {

    private final SecurityLogResource securityLogResource;
    private final SystemInfoResource systemInfoResource;
    private final SecurityAnalysisPrompts securityAnalysisPrompts;
    private final SecurityCommandCompletion securityCommandCompletion;

    private final NetworkScanTool networkScanTool;
    private final LogAnalysisTool logAnalysisTool;
    private final ThreatIntelligenceTool threatIntelligenceTool;
    private final FileQuarantineTool fileQuarantineTool;
    private final ProcessKillTool processKillTool;
    private final NetworkIsolationTool networkIsolationTool;
    private final AuditLogQueryTool auditLogQueryTool;
    private final IpBlockingTool ipBlockingTool;
    private final SessionTerminationTool sessionTerminationTool;

    @Bean
    public ToolCallbackProvider mcpToolProvider() {
        
        ToolCallbackProvider provider = MethodToolCallbackProvider.builder()
                .toolObjects(
                        networkScanTool,
                        logAnalysisTool,
                        threatIntelligenceTool,
                        fileQuarantineTool,
                        processKillTool,
                        networkIsolationTool,
                        auditLogQueryTool,
                        ipBlockingTool,
                        sessionTerminationTool
                )
                .build();

        return provider;
    }

    @Bean
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources() {
        
        List<McpServerFeatures.SyncResourceSpecification> resources = new ArrayList<>();

        resources.add(securityLogResource.createSpecification());

        resources.add(systemInfoResource.createSpecification());

        return resources;
    }

    @Bean
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts() {
        
        List<McpServerFeatures.SyncPromptSpecification> prompts = new ArrayList<>();

        prompts.add(securityAnalysisPrompts.createLogAnalysisSpec());

        prompts.add(securityAnalysisPrompts.createThreatAssessmentSpec());

        return prompts;
    }

    @Bean
    public List<McpServerFeatures.SyncCompletionSpecification> mcpCompletions() {
        
        List<McpServerFeatures.SyncCompletionSpecification> completions = new ArrayList<>();

        var completionInfo = securityCommandCompletion.createCompletionSpecification();
        if (completionInfo != null) {
                    } else {
            log.warn("  Completion 정보 생성 실패");
        }

        return completions;
    }

    @Bean
    public McpServerInfoLogger mcpServerInfoLogger() {
        return new McpServerInfoLogger();
    }

    public static class McpServerInfoLogger {

        public McpServerInfoLogger() {
                                                                                                                                                                                                                                                                                                                    }
    }
}