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
        log.info("MCP Tool Provider 등록 시작");

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

        log.info("{} 개의 @Tool 도구가 MCP를 통해 노출됩니다.", 6);

        return provider;
    }


    
    @Bean
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources() {
        log.info("📁 MCP Resources 등록 시작");

        List<McpServerFeatures.SyncResourceSpecification> resources = new ArrayList<>();

        
        resources.add(securityLogResource.createSpecification());
        log.info("  Resource 등록: Security Logs (security://logs/current)");

        
        resources.add(systemInfoResource.createSpecification());
        log.info("  Resource 등록: System Info (security://system/info)");

        log.info("총 {} 개의 Resource가 MCP를 통해 노출됩니다.", resources.size());

        return resources;
    }

    
    @Bean
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts() {
        log.info("MCP Prompts 등록 시작");

        List<McpServerFeatures.SyncPromptSpecification> prompts = new ArrayList<>();

        
        prompts.add(securityAnalysisPrompts.createLogAnalysisSpec());
        log.info("  Prompt 등록: analyze_security_logs");

        
        prompts.add(securityAnalysisPrompts.createThreatAssessmentSpec());
        log.info("  Prompt 등록: assess_threat_level");

        log.info("총 {} 개의 Prompt가 MCP를 통해 노출됩니다.", prompts.size());

        return prompts;
    }

    
    @Bean
    public List<McpServerFeatures.SyncCompletionSpecification> mcpCompletions() {
        log.info("🔤 MCP Completions 등록 시작");

        List<McpServerFeatures.SyncCompletionSpecification> completions = new ArrayList<>();

        
        var completionInfo = securityCommandCompletion.createCompletionSpecification();
        if (completionInfo != null) {
            log.info("  Completion 정보 생성: {} - {} 개 명령어",
                    completionInfo.get("name"),
                    completionInfo.get("totalCommands"));
        } else {
            log.warn("  Completion 정보 생성 실패");
        }

        log.info("총 {} 개의 Completion이 MCP를 통해 노출됩니다.", completions.size());

        return completions;
    }

    
    @Bean
    public McpServerInfoLogger mcpServerInfoLogger() {
        return new McpServerInfoLogger();
    }

    
    public static class McpServerInfoLogger {

        public McpServerInfoLogger() {
            log.info("=====================================");
            log.info("     MCP Server Configuration");
            log.info("=====================================");
            log.info("MCP 서버가 활성화되었습니다.");
            log.info("");
            log.info("도구 등록 방식:");
            log.info("  - @Component + @Tool 어노테이션 → 자동 등록");
            log.info("  - BaseSecurityTool 구현 → ToolCallback으로 자동 수집");
            log.info("  - Spring AI McpServerAutoConfiguration이 자동 처리");
            log.info("");
            log.info("📁 Resources: SecurityLogResource, SystemInfoResource");
            log.info("Prompts: SecurityAnalysisPrompts");
            log.info("🔤 Completions: SecurityCommandCompletion");
            log.info("");
            log.info("STDIO 모드로 실행:");
            log.info("  java -jar app.jar | mcp-client");
            log.info("");
            log.info("SSE 모드로 실행:");
            log.info("  spring-ai-starter-mcp-server-webmvc 의존성 필요");
            log.info("");
            log.info("설정 파일(application.yml):");
            log.info("  spring.ai.mcp.server.enabled=true");
            log.info("  spring.ai.mcp.server.type=SYNC");
            log.info("  spring.ai.mcp.server.name=contexa SOAR Platform");
            log.info("=====================================");
        }
    }
}