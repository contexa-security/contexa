package io.contexa.contexacoreenterprise.soar.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
@RequiredArgsConstructor
public class SoarPromptTemplate implements PromptTemplate {

     private final BeanOutputConverter<SoarResponse> responseConverter =
         new BeanOutputConverter<>(SoarResponse.class);

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

    @Override
    public Class<?> getAIGenerationType() {
        return SoarResponse.class;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("Soar");
    }

    @Override
    public String generateSystemPrompt(AIRequest<?> request, String systemMetadata) {
                
        StringBuilder prompt = new StringBuilder();

        boolean isToolExecutionMode = false;
        boolean isResponseGenerationMode = false;

        if (systemMetadata != null && !systemMetadata.trim().isEmpty()) {
            prompt.append("\n\n시스템 컨텍스트: ");
            prompt.append(systemMetadata);
        }

        return prompt.toString();
    }

    @Override
    public String generateUserPrompt(AIRequest<?> request, String contextInfo) {
        StringBuilder prompt = new StringBuilder();

        TemplateType templateType = request.getPromptTemplate();
        if (templateType != null && !templateType.name().isEmpty()) {
            prompt.append(templateType);
            prompt.append("\n");
        }

        if (contextInfo != null && !contextInfo.trim().isEmpty()) {
            prompt.append("\n컨텍스트: ");
            prompt.append(contextInfo);
            prompt.append("\n");
        }

        if (request.getContext() instanceof SoarContext soarContext) {
            if (soarContext.getIncidentId() != null || soarContext.getThreatLevel() != null) {
                prompt.append("\n");
                appendSoarContext(prompt, soarContext);
            }
        }
        
        return prompt.toString();
    }

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