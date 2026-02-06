package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
public class PolicyGenerationTemplate implements PromptTemplate {

    private final BeanOutputConverter<PolicyResponse> converter = 
        new BeanOutputConverter<>(PolicyResponse.class);

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("PolicyGeneration");
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            당신은 자연어 요구사항을 구조화된 접근 제어 정책으로 변환하는 IAM 정책 생성 AI입니다.

            중요: 응답은 반드시 PolicyResponse 스키마와 일치하는 순수 JSON 형식이어야 합니다.
            언어: 정책 이름과 설명은 반드시 한국어로 작성하세요.

            정책 생성 가이드라인:
            1. 자연어 요구사항과 컨텍스트를 분석하세요
            2. 요구사항을 역할, 권한, 조건에 매핑하세요
            3. 창의적이고 명확한 정책 이름을 생성하세요
            4. 정책을 설명하는 상세한 설명을 작성하세요
            5. 최소 권한 원칙을 적용하세요
            6. 필요한 경우 위험 평가를 포함하세요

            정책 구성요소:
            - policyName: 한국어로 된 명확하고 설명적인 이름
            - description: 한국어로 된 상세 설명
            - roleIds: 숫자 역할 ID 배열
            - permissionIds: 숫자 권한 ID 배열
            - conditions: 키가 반드시 숫자 조건 템플릿 ID(사용 가능한 항목에서 제공)이고 값이 문자열 배열인 맵. 설명적 문자열을 키로 절대 사용 금지
            - aiRiskAssessmentEnabled: AI 위험 평가 활성화 여부
            - requiredTrustScore: 신뢰도 점수 임계값 (0.0-1.0)
            - customConditionSpel: 사용자 정의 조건용 SpEL 표현식
            - effect: ALLOW 또는 DENY
            - policyConfidenceScore: 정책 생성에 대한 AI 신뢰도 (0.0-1.0)
            - appliedRules: 적용된 비즈니스 규칙 배열
            - optimized: 정책 최적화 여부

            %s

            비즈니스 규칙 패턴:
            - 시간 기반 접근: 업무시간, 유지보수 시간대
            - 위치 기반: IP 대역, 지리적 제한
            - 위험 기반: 신뢰도 점수, 행동 분석
            - 직무 분리: 충돌하는 역할 제한
            - 승인 워크플로우: 다중 인증 방식

            SpEL 표현식 예시:
            - #user.department == 'IT' && #time.hour >= 9 && #time.hour <= 18
            - #request.ip.startsWith('192.168.') || #user.hasRole('ADMIN')
            - #resource.classification == 'CONFIDENTIAL' && #user.clearanceLevel >= 3

            %s
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalLanguageQuery = extractQueryFromRequest(request);

        String policyRequest = String.format("""
            자연어로부터 IAM 정책 생성:

            자연어 요구사항:
            "%s"

            컨텍스트 정보:
            %s

            정책 생성 요구사항:
            1. 자연어를 분석하여 다음을 식별하세요:
               - 누가 접근이 필요한지 (역할/사용자)
               - 무엇에 접근해야 하는지 (리소스/권한)
               - 언제 접근이 허용되는지 (시간 조건)
               - 어디서 접근이 허용되는지 (위치 조건)
               - 왜 접근이 필요한지 (비즈니스 사유)

            2. 정책 구성요소에 매핑하세요:
               - 적절한 역할 ID 선택
               - 관련 권한 ID 선택
               - 필요한 조건 정의
               - 위험 평가 요구사항 설정
               - 필요시 SpEL 표현식 작성

            3. PolicyResponse 생성 시 포함 사항:
               - 명확한 한국어 정책 이름과 설명
               - 적절한 역할 및 권한 매핑
               - 잘 구조화된 조건
               - 생성 품질을 나타내는 신뢰도 점수
               - 적용된 비즈니스 규칙 목록
               - 최적화 상태

            중요 사항:
            - "conditions" 키는 반드시 제공된 조건 목록의 숫자 ID여야 하며, 설명적 문자열이 아닙니다
            - 조건 값은 문자열 배열이어야 합니다: ["value1", "value2"]
            - 객체 배열이 아닙니다: [{"key": "value"}]
            - 적용 가능한 조건이 없으면 "conditions"를 {}로 설정하세요
            - 정책 이름과 설명은 한국어로 작성하세요
            - 최소 권한 원칙을 적용하세요
            - 민감한 작업에 대해 위험 평가를 포함하세요

            완전한 PolicyResponse를 JSON 형식으로 생성하세요.
            """, naturalLanguageQuery, contextInfo);

        return policyRequest + "\n\n" + converter.getFormat();
    }

    private String extractQueryFromRequest(AIRequest<? extends DomainContext> request) {
        
        String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalLanguageQuery != null) {
            return naturalLanguageQuery;
        }

        if (request.getContext() != null) {
            return request.getContext().toString();
        }

        return "자연어 요구사항이 제공되지 않았습니다";
    }

    public BeanOutputConverter<PolicyResponse> getConverter() {
        return converter;
    }
} 