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

/**
 * SOAR Tool 실행 서비스
 * Spring AI 1.0.0의 실제 ToolCallback 시스템 활용한 완전한 Human-in-the-Loop 구현
 */
@Slf4j
@RequiredArgsConstructor
public class SoarToolExecutionService {
    
    private final ToolCapableLLMClient toolCapableLLMClient;
    private final ChainedToolResolver toolResolver;
    
    /**
     * Human-in-the-Loop가 적용된 Tool 실행
     * Spring AI 1.0.0의 실제 ToolCallback 시스템 완전 활용
     */
    public Mono<String> executeWithHumanApproval(String userPrompt, String incidentId, String organizationId) {
        log.info("SOAR Tool 실행 시작: Human-in-the-Loop 활성화");
        log.info("사용자 프롬프트: {}", userPrompt);
        log.info("🆔 인시던트 ID: {}, 조직 ID: {}", incidentId, organizationId);
        
        // SOAR ToolCallback 목록 조회 (승인 메커니즘 포함)
        ToolCallback[] soarToolCallbacks = getSoarToolCallbacks();
        
        // Prompt 생성 - SOAR 컨텍스트 포함
        String enhancedPrompt = enhancePromptWithSoarContext(userPrompt, incidentId, organizationId);
        Prompt prompt = new Prompt(enhancedPrompt);
        
        // ToolCapableLLMClient.callToolCallbacks() 활용
        // 실제 Spring AI ToolCallback 시스템 사용
        return toolCapableLLMClient.callToolCallbacks(prompt, soarToolCallbacks)
            .doOnSuccess(result -> 
                log.info("SOAR Tool 실행 완료 - 인시던트: {}", incidentId))
            .doOnError(error -> 
                log.error("SOAR Tool 실행 실패 - 인시던트: {}", incidentId, error));
    }
    
    /**
     * 스트리밍 방식 Tool 실행
     */
    public Flux<String> streamWithHumanApproval(String userPrompt, String incidentId, String organizationId) {
        log.info("SOAR Tool 스트림 실행 시작: Human-in-the-Loop 활성화");
        
        ToolCallback[] soarToolCallbacks = getSoarToolCallbacks();
        String enhancedPrompt = enhancePromptWithSoarContext(userPrompt, incidentId, organizationId);
        Prompt prompt = new Prompt(enhancedPrompt);
        
        return toolCapableLLMClient.streamToolCallbacks(prompt, soarToolCallbacks)
            .doOnComplete(() -> 
                log.info("SOAR Tool 스트림 완료 - 인시던트: {}", incidentId))
            .doOnError(error -> 
                log.error("SOAR Tool 스트림 실패 - 인시던트: {}", incidentId, error));
    }
    
    /**
     * SOAR ToolCallback 목록 조회
     * SoarToolCallbackResolver를 통해 승인 메커니즘이 통합된 ToolCallback 조회
     */
    private ToolCallback[] getSoarToolCallbacks() {
        return toolResolver.getAllToolCallbacks();
    }
    
    /**
     * SOAR 컨텍스트가 포함된 프롬프트 생성
     */
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
    
    /**
     * 등록된 SOAR 도구 목록 조회
     */
    public java.util.Set<String> getRegisteredTools() {
        return toolResolver.getRegisteredToolNames();
    }
    
    /**
     * SOAR 도구 실행 통계
     */
    public Map<String, Object> getExecutionStatistics() {
        return toolResolver.getToolStatistics();
    }
    
    /**
     * 특정 도구 실행 (단일 도구 테스트용)
     */
    public String executeToolDirectly(String toolName, String toolInput) {
        log.info("직접 도구 실행: {} with input: {}", toolName, toolInput);
        
        ToolCallback toolCallback = toolResolver.resolve(toolName);
        if (toolCallback == null) {
            throw new IllegalArgumentException("도구를 찾을 수 없습니다: " + toolName);
        }
        
        try {
            String result = toolCallback.call(toolInput);
            log.info("도구 실행 성공: {}", toolName);
            return result;
        } catch (Exception e) {
            log.error("도구 실행 실패: {}", toolName, e);
            throw new RuntimeException("도구 실행 실패: " + e.getMessage(), e);
        }
    }
}