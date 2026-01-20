package io.contexa.autoconfigure.enterprise.mcp;

import io.contexa.autoconfigure.properties.ContexaEnterpriseProperties;
import io.contexa.contexacoreenterprise.mcp.tool.execution.config.ToolExecutionProperties;
import io.contexa.contexamcp.completions.SecurityCommandCompletion;
import io.contexa.contexamcp.prompts.SecurityAnalysisPrompts;
import io.contexa.contexamcp.resources.SecurityLogResource;
import io.contexa.contexamcp.resources.SystemInfoResource;
import io.contexa.contexamcp.tools.*;
import io.contexa.contexamcp.service.AuditLogService;
import io.contexa.contexamcp.service.IpBlockingService;
import io.contexa.contexamcp.service.UserSessionService;
import io.modelcontextprotocol.server.McpServerFeatures;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.List;



@Slf4j
@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexamcp.tools.NetworkScanTool")
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@ConditionalOnProperty(
    prefix = "spring.ai.mcp.server",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties({
    ContexaEnterpriseProperties.class,
    ToolExecutionProperties.class
})
public class EnterpriseMcpAutoConfiguration {

    
    
    

    
    @Bean
    @ConditionalOnMissingBean
    public NetworkScanTool networkScanTool() {
        return new NetworkScanTool();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public LogAnalysisTool logAnalysisTool() {
        return new LogAnalysisTool();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public ThreatIntelligenceTool threatIntelligenceTool() {
        return new ThreatIntelligenceTool();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public FileQuarantineTool fileQuarantineTool() {
        return new FileQuarantineTool();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public ProcessKillTool processKillTool() {
        return new ProcessKillTool();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public NetworkIsolationTool networkIsolationTool() {
        return new NetworkIsolationTool();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public AuditLogQueryTool auditLogQueryTool(AuditLogService auditLogService) {
        return new AuditLogQueryTool(auditLogService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public IpBlockingTool ipBlockingTool(IpBlockingService ipBlockingService) {
        return new IpBlockingTool(ipBlockingService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SessionTerminationTool sessionTerminationTool(UserSessionService userSessionService) {
        return new SessionTerminationTool(userSessionService);
    }

    
    
    

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityLogResource securityLogResource(ObjectMapper objectMapper) {
        return new SecurityLogResource(objectMapper);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SystemInfoResource systemInfoResource(ObjectMapper objectMapper) {
        return new SystemInfoResource(objectMapper);
    }

    
    
    

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityAnalysisPrompts securityAnalysisPrompts() {
        return new SecurityAnalysisPrompts();
    }

    
    
    

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityCommandCompletion securityCommandCompletion() {
        return new SecurityCommandCompletion();
    }

    
    
    

    
    @Bean
    @ConditionalOnMissingBean
    public ToolCallbackProvider mcpToolProvider(
            NetworkScanTool networkScanTool,
            LogAnalysisTool logAnalysisTool,
            ThreatIntelligenceTool threatIntelligenceTool,
            FileQuarantineTool fileQuarantineTool,
            ProcessKillTool processKillTool,
            NetworkIsolationTool networkIsolationTool,
            AuditLogQueryTool auditLogQueryTool,
            IpBlockingTool ipBlockingTool,
            SessionTerminationTool sessionTerminationTool) {

        log.info("Enterprise MCP Tool Provider 등록 시작");

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

        log.info("{} 개의 Enterprise @Tool 도구가 MCP를 통해 노출됩니다.", 9);

        return provider;
    }

    
    @Bean
    @ConditionalOnMissingBean(name = "mcpResources")
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources(
            SecurityLogResource securityLogResource,
            SystemInfoResource systemInfoResource) {

        log.info("Enterprise MCP Resources 등록 시작");

        List<McpServerFeatures.SyncResourceSpecification> resources = new ArrayList<>();

        
        resources.add(securityLogResource.createSpecification());
        log.info("  Resource 등록: Security Logs (security://logs/current)");

        
        resources.add(systemInfoResource.createSpecification());
        log.info("  Resource 등록: System Info (security://system/info)");

        log.info("총 {} 개의 Resource가 MCP를 통해 노출됩니다.", resources.size());

        return resources;
    }

    
    @Bean
    @ConditionalOnMissingBean(name = "mcpPrompts")
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts(
            SecurityAnalysisPrompts securityAnalysisPrompts) {

        log.info("Enterprise MCP Prompts 등록 시작");

        List<McpServerFeatures.SyncPromptSpecification> prompts = new ArrayList<>();

        
        prompts.add(securityAnalysisPrompts.createLogAnalysisSpec());
        log.info("  Prompt 등록: analyze_security_logs");

        
        prompts.add(securityAnalysisPrompts.createThreatAssessmentSpec());
        log.info("  Prompt 등록: assess_threat_level");

        log.info("총 {} 개의 Prompt가 MCP를 통해 노출됩니다.", prompts.size());

        return prompts;
    }

    
    @Bean
    @ConditionalOnMissingBean(name = "mcpCompletions")
    public List<McpServerFeatures.SyncCompletionSpecification> mcpCompletions(
            SecurityCommandCompletion securityCommandCompletion) {

        log.info("Enterprise MCP Completions 등록 시작");

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
    @ConditionalOnMissingBean
    public McpServerInfoLogger mcpServerInfoLogger() {
        return new McpServerInfoLogger();
    }

    
    public static class McpServerInfoLogger {

        public McpServerInfoLogger() {
            log.info("=====================================");
            log.info("  Enterprise MCP Server Configuration");
            log.info("=====================================");
            log.info("Enterprise MCP 서버가 활성화되었습니다.");
            log.info("");
            log.info("도구 등록 방식:");
            log.info("  - @Component + @Tool 어노테이션 → 자동 등록");
            log.info("  - BaseSecurityTool 구현 → ToolCallback으로 자동 수집");
            log.info("  - Spring AI McpServerAutoConfiguration이 자동 처리");
            log.info("");
            log.info("Resources: SecurityLogResource, SystemInfoResource");
            log.info("Prompts: SecurityAnalysisPrompts");
            log.info("Completions: SecurityCommandCompletion");
            log.info("");
            log.info("STDIO 모드로 실행:");
            log.info("  java -jar app.jar | mcp-client");
            log.info("");
            log.info("SSE 모드로 실행:");
            log.info("  spring-ai-starter-mcp-server-webmvc 의존성 필요");
            log.info("");
            log.info("설정 파일(application.yml):");
            log.info("  contexa.enterprise.enabled=true");
            log.info("  spring.ai.mcp.server.enabled=true");
            log.info("  spring.ai.mcp.server.type=SYNC");
            log.info("  spring.ai.mcp.server.name=contexa SOAR Platform Enterprise");
            log.info("=====================================");
        }
    }
}
