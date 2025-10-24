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
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * MCP Tool Configuration (Simplified)
 * 
 * Spring AI의 McpServerAutoConfiguration이 자동으로 도구들을 수집하고 등록하므로
 * 이 설정 클래스는 Resources, Prompts, Completions만 관리합니다.
 * 
 * 도구 등록 방식:
 * - @Component + @Tool 어노테이션을 가진 클래스들은 자동으로 등록됨
 * - BaseSecurityTool을 구현한 클래스들은 ToolCallback으로 자동 수집됨
 * - Spring AI가 중복 제거 및 스키마 생성을 자동 처리
 * 
 * @see org.springframework.ai.mcp.server.autoconfigure.McpServerAutoConfiguration
 */
@Slf4j
@Configuration
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


    /**
     * @Tool 어노테이션이 있는 도구들을 MCP에 노출
     * Spring AI 예제 패턴을 따름
     */
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


    /**
     * MCP Resources 등록
     * 보안 로그, 시스템 정보 등을 리소스로 노출
     */
    @Bean
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources() {
        log.info("📁 MCP Resources 등록 시작");

        List<McpServerFeatures.SyncResourceSpecification> resources = new ArrayList<>();

        // 보안 로그 리소스
        resources.add(securityLogResource.createSpecification());
        log.info("  Resource 등록: Security Logs (security://logs/current)");

        // 시스템 정보 리소스
        resources.add(systemInfoResource.createSpecification());
        log.info("  Resource 등록: System Info (security://system/info)");

        log.info("총 {} 개의 Resource가 MCP를 통해 노출됩니다.", resources.size());

        return resources;
    }

    /**
     * MCP Prompts 등록
     * 보안 분석을 위한 프롬프트 템플릿 제공
     */
    @Bean
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts() {
        log.info("MCP Prompts 등록 시작");

        List<McpServerFeatures.SyncPromptSpecification> prompts = new ArrayList<>();

        // 로그 분석 프롬프트
        prompts.add(securityAnalysisPrompts.createLogAnalysisSpec());
        log.info("  Prompt 등록: analyze_security_logs");

        // 위협 평가 프롬프트
        prompts.add(securityAnalysisPrompts.createThreatAssessmentSpec());
        log.info("  Prompt 등록: assess_threat_level");

        log.info("총 {} 개의 Prompt가 MCP를 통해 노출됩니다.", prompts.size());

        return prompts;
    }

    /**
     * MCP Completions 등록
     * 보안 명령어 자동 완성 기능
     *
     * 현재 Spring AI MCP의 Completion API가 완전히 정의되지 않아 비활성화
     */
    @Bean
    public List<McpServerFeatures.SyncCompletionSpecification> mcpCompletions() {
        log.info("🔤 MCP Completions 등록 시작");

        List<McpServerFeatures.SyncCompletionSpecification> completions = new ArrayList<>();

        // SecurityCommandCompletion의 새로운 메서드 사용
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

    /**
     * MCP 서버 정보 로깅
     * 애플리케이션 시작 시 MCP 설정 정보를 출력
     */
    @Bean
    public McpServerInfoLogger mcpServerInfoLogger() {
        return new McpServerInfoLogger();
    }

    /**
     * MCP 서버 정보 로거
     * 
     * 시작 시 MCP 서버 구성 정보를 로깅하여 운영자가 확인할 수 있도록 함
     */
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
            log.info("  spring.ai.mcp.server.name=AI3Security SOAR Platform");
            log.info("=====================================");
        }
    }
}