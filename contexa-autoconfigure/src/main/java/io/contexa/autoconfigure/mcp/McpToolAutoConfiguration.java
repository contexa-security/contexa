package io.contexa.autoconfigure.mcp;

import io.contexa.contexamcp.completions.SecurityCommandCompletion;
import io.contexa.contexamcp.prompts.SecurityAnalysisPrompts;
import io.contexa.contexamcp.resources.SecurityLogResource;
import io.contexa.contexamcp.resources.SystemInfoResource;
import io.contexa.contexamcp.tools.*;
import io.modelcontextprotocol.server.McpServerFeatures;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.List;

/**
 * MCP Tool AutoConfiguration
 *
 * <p>
 * MCP (Model Context Protocol) 도구 시스템 자동 구성
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>ToolCallbackProvider - MCP Tool Provider</li>
 *   <li>List&lt;SyncResourceSpecification&gt; - MCP Resources (보안 로그, 시스템 정보)</li>
 *   <li>List&lt;SyncPromptSpecification&gt; - MCP Prompts (보안 분석)</li>
 *   <li>List&lt;SyncCompletionSpecification&gt; - MCP Completions (명령어 자동 완성)</li>
 *   <li>McpServerInfoLogger - MCP 서버 정보 로거</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * spring:
 *   ai:
 *     mcp:
 *       server:
 *         enabled: true  # (기본값)
 * </pre>
 *
 * <h3>자동 스캔 컴포넌트:</h3>
 * <ul>
 *   <li>Services: AuditLogService, IpBlockingService, UserSessionService</li>
 *   <li>Resources: SecurityLogResource, SystemInfoResource</li>
 *   <li>Prompts: SecurityAnalysisPrompts</li>
 *   <li>Completions: SecurityCommandCompletion</li>
 *   <li>Event Listeners: SimpleToolEventListener</li>
 *   <li>Tools: 9개 MCP Tool 구현체 (@Component + @Tool)</li>
 * </ul>
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "spring.ai.mcp.server",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class McpToolAutoConfiguration {

    /**
     * MCP Tool Provider 등록
     *
     * <p>
     * @Tool 어노테이션이 있는 도구들을 MCP에 노출합니다.
     * Spring AI 예제 패턴을 따릅니다.
     * </p>
     *
     * @param networkScanTool 네트워크 스캔 도구
     * @param logAnalysisTool 로그 분석 도구
     * @param threatIntelligenceTool 위협 인텔리전스 도구
     * @param fileQuarantineTool 파일 격리 도구
     * @param processKillTool 프로세스 종료 도구
     * @param networkIsolationTool 네트워크 격리 도구
     * @param auditLogQueryTool 감사 로그 조회 도구
     * @param ipBlockingTool IP 차단 도구
     * @param sessionTerminationTool 세션 종료 도구
     * @return ToolCallbackProvider
     */
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

        log.info("{} 개의 @Tool 도구가 MCP를 통해 노출됩니다.", 9);

        return provider;
    }

    /**
     * MCP Resources 등록
     *
     * <p>
     * 보안 로그, 시스템 정보 등을 리소스로 노출합니다.
     * </p>
     *
     * @param securityLogResource 보안 로그 리소스
     * @param systemInfoResource 시스템 정보 리소스
     * @return MCP 리소스 목록
     */
    @Bean
    @ConditionalOnMissingBean(name = "mcpResources")
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources(
            SecurityLogResource securityLogResource,
            SystemInfoResource systemInfoResource) {

        log.info("MCP Resources 등록 시작");

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
     *
     * <p>
     * 보안 분석을 위한 프롬프트 템플릿을 제공합니다.
     * </p>
     *
     * @param securityAnalysisPrompts 보안 분석 프롬프트
     * @return MCP 프롬프트 목록
     */
    @Bean
    @ConditionalOnMissingBean(name = "mcpPrompts")
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts(
            SecurityAnalysisPrompts securityAnalysisPrompts) {

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
     *
     * <p>
     * 보안 명령어 자동 완성 기능을 제공합니다.
     * </p>
     *
     * <p>
     * 현재 Spring AI MCP의 Completion API가 완전히 정의되지 않아
     * 빈 목록을 반환하지만, 향후 확장을 위해 구조를 유지합니다.
     * </p>
     *
     * @param securityCommandCompletion 보안 명령어 자동 완성
     * @return MCP 자동 완성 목록
     */
    @Bean
    @ConditionalOnMissingBean(name = "mcpCompletions")
    public List<McpServerFeatures.SyncCompletionSpecification> mcpCompletions(
            SecurityCommandCompletion securityCommandCompletion) {

        log.info("MCP Completions 등록 시작");

        List<McpServerFeatures.SyncCompletionSpecification> completions = new ArrayList<>();

        // SecurityCommandCompletion의 정보 생성
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
     * MCP 서버 정보 로거
     *
     * <p>
     * 애플리케이션 시작 시 MCP 설정 정보를 출력하여
     * 운영자가 확인할 수 있도록 합니다.
     * </p>
     *
     * @return MCP 서버 정보 로거
     */
    @Bean
    @ConditionalOnMissingBean
    public McpServerInfoLogger mcpServerInfoLogger() {
        return new McpServerInfoLogger();
    }

    /**
     * MCP 서버 정보 로거
     *
     * <p>
     * 시작 시 MCP 서버 구성 정보를 로깅하여 운영자가 확인할 수 있도록 합니다.
     * </p>
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
            log.info("  spring.ai.mcp.server.enabled=true");
            log.info("  spring.ai.mcp.server.type=SYNC");
            log.info("  spring.ai.mcp.server.name=contexa SOAR Platform");
            log.info("=====================================");
        }
    }
}
