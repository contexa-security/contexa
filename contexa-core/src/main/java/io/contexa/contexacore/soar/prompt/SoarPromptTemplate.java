package io.contexa.contexacore.soar.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.mcp.integration.McpPromptIntegrator;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * 개선된 SOAR 프롬프트 템플릿 V3
 * 
 * 단순하면서도 완벽한 프롬프트 생성을 담당합니다.
 * - 기본 SOAR 역할 정의
 * - 도구 섹션 생성 (위험도별 분류 포함)
 * - MCP 프롬프트 선택적 오버라이드
 * - 불필요한 복잡성 제거
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Component
@PromptTemplateConfig(
    key = "soarAnalysis",
    aliases = {"soar_analysis", "security_analysis"},
    description = "SOAR Security Analysis and Response Template with Tool Support"
)
@RequiredArgsConstructor
public class SoarPromptTemplate implements PromptTemplate {
    
    /**
     * 구조화된 출력을 위한 컨버터
     * 도구 실행 모드에서는 비활성화하여 충돌 방지
     */
     private final BeanOutputConverter<SoarResponse> responseConverter =
         new BeanOutputConverter<>(SoarResponse.class);

    /**
     * 도구 실행 전용 시스템 역할 - 도구 호출에만 집중
     */
    private static final String TOOL_EXECUTION_ROLE = """
        당신은 SOAR 보안 도구 실행 시스템입니다.
        
        현재 단계: 도구 함수 호출 단계
        
        중요 지시사항:
        1. 제공된 도구 함수(function)를 직접 호출하세요
        2. 텍스트 응답을 생성하지 마세요
        3. JSON 문자열을 생성하지 마세요
        4. 오직 함수 호출(function calling)만 수행하세요
        
        사용 가능한 보안 도구들:
        - ip_blocking: IP 주소 차단
        - network_isolation: 네트워크 격리
        - process_kill: 악성 프로세스 종료
        - session_termination: 세션 종료
        - file_quarantine: 파일 격리
        
        각 도구는 함수로 제공되며, 적절한 파라미터와 함께 호출하세요.
        도구 설명이나 JSON 텍스트를 생성하는 것이 아니라,
        실제 함수 호출을 수행해야 합니다.
        """;
    
    /**
     * 응답 생성 전용 시스템 역할 - JSON 응답 생성에만 집중
     */
    private static final String RESPONSE_GENERATION_ROLE = """
        당신은 SOAR 보안 분석 시스템입니다.

        현재 단계: 최종 분석 및 응답 생성 단계

        도구 실행이 완료되었습니다. 이제 수집된 데이터를 바탕으로 종합적인 보안 분석을 수행하세요.

        응답 생성 규칙:
        1. 도구 실행 결과를 종합적으로 분석하세요
        2. 위협 수준을 평가하세요
        3. 구체적인 권장 조치를 제시하세요
        4. 반드시 유효한 JSON 형식의 SoarResponse를 생성하세요

        중요: 이 단계에서는 추가 도구 호출을 하지 마세요.
        """;
    
    /**
     * AI 생성 타입 반환 (Spring AI 표준)
     */
    @Override
    public Class<?> getAIGenerationType() {
        return SoarResponse.class;
    }
    
    /**
     * 시스템 프롬프트 생성 (메인 메서드)
     * 도구 실행 모드와 응답 생성 모드를 명확히 분리
     */
    @Override
    public String generateSystemPrompt(AIRequest<?> request, String systemMetadata) {
        log.debug("SOAR 시스템 프롬프트 생성 시작");
        
        StringBuilder prompt = new StringBuilder();
        
        // 도구 실행 모드 판단
        boolean isToolExecutionMode = false;
        boolean isResponseGenerationMode = false;
        
       /* if (request.getContext() instanceof SoarContext soarContext) {
            // 도구 실행이 필요한 경우 - 초기 상태에서만
            isToolExecutionMode = soarContext.isRequiresToolExecution() && 
                                 (soarContext.getExecutedTools() == null || 
                                  soarContext.getExecutedTools().isEmpty());
            
            // 도구 실행이 이미 완료된 경우
            isResponseGenerationMode = soarContext.getExecutedTools() != null && 
                                      !soarContext.getExecutedTools().isEmpty();
        }*/
        
       /* if (isToolExecutionMode) {
            // 도구 실행 모드: JSON 스키마 없이 도구 호출에만 집중
            log.info("도구 실행 모드 활성화 - BeanOutputConverter 비활성화");
//            prompt.append(TOOL_EXECUTION_ROLE);
            
            // 중요: 도구 실행 시에는 JSON 스키마를 추가하지 않음!
            // Spring AI가 도구 호출을 잘 할 수 있도록 프롬프트만 제공
            
        } else if (isResponseGenerationMode) {
            // 응답 생성 모드: JSON 스키마와 함께 최종 응답 생성
            log.info("응답 생성 모드 활성화 - BeanOutputConverter 활성화");
            prompt.append(RESPONSE_GENERATION_ROLE);
            
            // 응답 생성 시에만 JSON 스키마 추가
            prompt.append("\n\n다음 JSON 스키마에 따라 SoarResponse 객체를 생성하세요:");
            String formatInstructions = responseConverter.getFormat();
            prompt.append("\n\n").append(formatInstructions);
            
        } else {
            // 기본 모드: 도구 없이 직접 분석 및 응답
            log.info("기본 분석 모드 활성화");
            prompt.append(RESPONSE_GENERATION_ROLE);
            
            // 기본 모드에서도 JSON 스키마 추가
            prompt.append("\n\n다음 JSON 스키마에 따라 SoarResponse 객체를 생성하세요:");
            String formatInstructions = responseConverter.getFormat();
            prompt.append("\n\n").append(formatInstructions);
        }*/

        // 시스템 메타데이터 추가 (있는 경우)
        if (systemMetadata != null && !systemMetadata.trim().isEmpty()) {
            prompt.append("\n\n시스템 컨텍스트: ");
            prompt.append(systemMetadata);
        }
        
        log.debug("SOAR 시스템 프롬프트 생성 완료: {} 문자, 모드: {}",
                 prompt.length(), 
                 isToolExecutionMode ? "도구실행" : 
                 (isResponseGenerationMode ? "응답생성" : "기본"));
        
        return prompt.toString();
    }
    
    /**
     * 사용자 프롬프트 생성 - Spring AI 표준 패턴
     */
    @Override
    public String generateUserPrompt(AIRequest<?> request, String contextInfo) {
        StringBuilder prompt = new StringBuilder();
        
        // 1. 사용자 요청
        String userInput = request.getPromptTemplate();
        if (userInput != null && !userInput.trim().isEmpty()) {
            prompt.append(userInput);
            prompt.append("\n");
        }
        
        // 2. 컨텍스트 정보
        if (contextInfo != null && !contextInfo.trim().isEmpty()) {
            prompt.append("\n컨텍스트: ");
            prompt.append(contextInfo);
            prompt.append("\n");
        }
        
        // 3. SOAR 컨텍스트
        if (request.getContext() instanceof SoarContext soarContext) {
            if (soarContext.getIncidentId() != null || soarContext.getThreatLevel() != null) {
                prompt.append("\n");
                appendSoarContext(prompt, soarContext);
            }
        }
        
        return prompt.toString();
    }


    /**
     * SOAR 컨텍스트 추가 - 단순화
     */
    private void appendSoarContext(StringBuilder prompt, SoarContext context) {
        if (context.getIncidentId() != null) {
            prompt.append("사건 ID: ").append(context.getIncidentId()).append("\n");
        }
        
        if (context.getThreatLevel() != null) {
            prompt.append("위협 수준: ").append(context.getThreatLevel()).append("\n");
        }
        
        if (context.getAffectedAssets() != null && !context.getAffectedAssets().isEmpty()) {
            prompt.append("영향받은 자산: ").append(
                String.join(", ", context.getAffectedAssets())
            ).append("\n");
        }
    }

}