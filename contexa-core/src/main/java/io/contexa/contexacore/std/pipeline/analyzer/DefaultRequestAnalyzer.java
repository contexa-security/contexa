package io.contexa.contexacore.std.pipeline.analyzer;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 기본 요청 분석기
 *
 * AI 요청의 복잡도, 컨텍스트 검색 필요성, 응답 속도 요구사항 등을 분석합니다.
 * 분석 결과는 파이프라인 최적화에 사용됩니다.
 */
@Slf4j
public class DefaultRequestAnalyzer implements RequestAnalyzer {

    @Override
    public <T extends DomainContext> RequestCharacteristics analyze(AIRequest<T> request) {
        log.debug("[RequestAnalyzer] 요청 분석 시작: {}", request.getRequestId());

        double complexity = calculateComplexity(request);
        boolean requiresContext = shouldUseContextRetrieval(request);
        boolean fastPath = requiresFastResponse(request);
        String requestType = classifyRequestType(request);
        int dataVolume = estimateDataVolume(request);

        RequestCharacteristics characteristics = RequestCharacteristics.builder()
                .complexity(complexity)
                .requiresContextRetrieval(requiresContext)
                .requiresFastResponse(fastPath)
                .requiresHighAccuracy(!fastPath) // 빠른 응답 필요하면 정확도 낮춤
                .estimatedDataVolume(dataVolume)
                .requestType(requestType)
                .metadata(extractMetadata(request))
                .build();

        log.info("[RequestAnalyzer] 분석 완료 - {}", characteristics);

        return characteristics;
    }

    /**
     * 요청 복잡도 계산
     */
    private <T extends DomainContext> double calculateComplexity(AIRequest<T> request) {
        double complexity = 0.0;

        // 1. 프롬프트 길이 기반 (0 ~ 0.3)
        String prompt = request.getPromptTemplate();
        if (prompt != null) {
            int promptLength = prompt.length();
            complexity += Math.min(promptLength / 1000.0, 0.3);
        }

        // 2. 컨텍스트 존재 여부 (0 ~ 0.3)
        T context = request.getContext();
        if (context != null) {
            // Context 객체가 있으면 복잡도 증가
            complexity += 0.2;
        }

        // 3. 진단 타입 기반 복잡도 (0 ~ 0.4)
        complexity += getDiagnosisTypeComplexity(request.getDiagnosisType());

        return Math.min(complexity, 1.0);
    }

    /**
     * 진단 타입별 복잡도
     */
    private double getDiagnosisTypeComplexity(DiagnosisType type) {
        if (type == null) {
            return 0.2;
        }

        switch (type) {
            case POLICY_GENERATION:
            case ACCESS_GOVERNANCE:
            case BEHAVIORAL_ANALYSIS:
                return 0.4; // 높은 복잡도
            case RISK_ASSESSMENT:
            case RESOURCE_NAMING:
            case SECURITY_COPILOT:
            case DYNAMIC_THREAT_RESPONSE:
                return 0.3; // 중간 복잡도
            case CONDITION_TEMPLATE:
            case STUDIO_QUERY:
                return 0.2; // 낮은 복잡도
            default:
                return 0.2;
        }
    }

    /**
     * 컨텍스트 검색 필요성 판단
     */
    private <T extends DomainContext> boolean shouldUseContextRetrieval(AIRequest<T> request) {
        // 명시적으로 컨텍스트 검색 불필요 표시가 있는 경우
        Boolean skipContext = request.getParameter("skipContextRetrieval", Boolean.class);
        if (skipContext != null && skipContext) {
            return false;
        }

        // 프롬프트에서 분류/조회 키워드 확인
        String prompt = request.getPromptTemplate();
        if (prompt != null) {
            String lowerPrompt = prompt.toLowerCase();
            if (lowerPrompt.contains("classify") ||
                    lowerPrompt.contains("simple") ||
                    lowerPrompt.contains("quick") ||
                    lowerPrompt.contains("단순") ||
                    lowerPrompt.contains("간단")) {
                return false;
            }
        }

        // 대부분의 경우 컨텍스트 검색 필요
        return true;
    }

    /**
     * 빠른 응답 필요성 판단
     */
    private <T extends DomainContext> boolean requiresFastResponse(AIRequest<T> request) {
        // 파라미터에서 명시적 지정 확인
        Boolean fastMode = request.getParameter("fastMode", Boolean.class);
        if (fastMode != null && fastMode) {
            return true;
        }

        // 스트리밍 요청은 빠른 응답 필요
        Boolean streaming = request.getParameter("streaming", Boolean.class);
        if (streaming != null && streaming) {
            return true;
        }

        return false;
    }

    /**
     * 요청 타입 분류
     */
    private <T extends DomainContext> String classifyRequestType(AIRequest<T> request) {
        String prompt = request.getPromptTemplate();
        if (prompt == null) {
            return "UNKNOWN";
        }

        String lowerPrompt = prompt.toLowerCase();
        if (lowerPrompt.contains("classify") || lowerPrompt.contains("categorize") ||
                lowerPrompt.contains("분류")) {
            return "CLASSIFICATION";
        } else if (lowerPrompt.contains("generate") || lowerPrompt.contains("create") ||
                lowerPrompt.contains("생성")) {
            return "GENERATION";
        } else if (lowerPrompt.contains("analyze") || lowerPrompt.contains("evaluate") ||
                lowerPrompt.contains("분석") || lowerPrompt.contains("평가")) {
            return "ANALYSIS";
        } else if (lowerPrompt.contains("synthesize") || lowerPrompt.contains("combine") ||
                lowerPrompt.contains("종합")) {
            return "SYNTHESIS";
        }

        return "GENERAL";
    }

    /**
     * 데이터 볼륨 추정
     */
    private <T extends DomainContext> int estimateDataVolume(AIRequest<T> request) {
        int volume = 0;

        // 프롬프트 크기
        if (request.getPromptTemplate() != null) {
            volume += request.getPromptTemplate().length();
        }

        // 컨텍스트 크기 추정
        if (request.getContext() != null) {
            volume += 500; // 평균 컨텍스트 크기
        }

        return volume;
    }

    /**
     * 메타데이터 추출
     */
    private <T extends DomainContext> Map<String, Object> extractMetadata(AIRequest<T> request) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("diagnosis_type", request.getDiagnosisType());
        metadata.put("request_id", request.getRequestId());
        return metadata;
    }

    @Override
    public String getAnalyzerName() {
        return "DefaultRequestAnalyzer";
    }
}
