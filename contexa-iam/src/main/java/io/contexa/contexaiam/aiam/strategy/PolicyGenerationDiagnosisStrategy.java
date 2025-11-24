package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics;
import io.contexa.contexacore.std.pipeline.condition.AlwaysExecuteCondition;
import io.contexa.contexacore.std.pipeline.condition.ContextRetrievalOptionalCondition;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 정책 생성 진단 전략 (리팩토링 버전)
 *
 * 기존 PolicyGenerationDiagnosisStrategy의 모든 기능을 유지하면서
 * 새로운 추상 클래스 구조를 활용하여 중복 코드 제거
 */
@Slf4j
public class PolicyGenerationDiagnosisStrategy extends AbstractAIStrategy<PolicyContext, PolicyResponse> {

    public PolicyGenerationDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.POLICY_GENERATION;
    }

    @Override
    public int getPriority() {
        return 15;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected void validateRequest(AIRequest<PolicyContext> request) throws DiagnosisException {
        if (request == null) {
            throw new DiagnosisException("POLICY_GENERATION", "NULL_REQUEST", "요청이 null입니다");
        }

        String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            throw new DiagnosisException("POLICY_GENERATION", "MISSING_NATURAL_LANGUAGE_QUERY",
                    "naturalLanguageQuery 파라미터가 필요합니다");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return AdvancedPolicyGenerationLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<PolicyContext> request) {
        return new PolicyGenerationRequest(
                request.getParameter("naturalLanguageQuery", String.class),
                request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class)
        );
    }

    @Override
    protected PolicyResponse processLabExecution(Object lab, Object labRequest, AIRequest<PolicyContext> request) throws Exception {
        AILab<PolicyGenerationRequest, PolicyResponse> policyGenerationLab = (AdvancedPolicyGenerationLab) lab;
        PolicyGenerationRequest policyGenerationRequest = (PolicyGenerationRequest) labRequest;

        log.info("정책 생성 요청: {}", policyGenerationRequest.getNaturalLanguageQuery());
        return policyGenerationLab.process(policyGenerationRequest);
    }

    @Override
    protected Mono<PolicyResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<PolicyContext> originRequest) {
        AILab<PolicyGenerationRequest, PolicyResponse> policyGenerationLab = (AdvancedPolicyGenerationLab) lab;
        PolicyGenerationRequest data = (PolicyGenerationRequest) labRequest;

        log.info("비동기 정책 생성 요청: {}", data.getNaturalLanguageQuery());
        return policyGenerationLab.processAsync(data);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<PolicyContext> request) {
        AILab<PolicyGenerationRequest, PolicyResponse> policyGenerationLab = (AdvancedPolicyGenerationLab) lab;
        PolicyGenerationRequest policyGenerationRequest = (PolicyGenerationRequest) labRequest;

        log.info("실시간 스트리밍 정책 생성 요청: {}", policyGenerationRequest.getNaturalLanguageQuery());
        if (policyGenerationRequest.getAvailableItems() != null) {
            log.info("사용 가능한 항목들 포함");
        }

        return policyGenerationLab.processStream(policyGenerationRequest);
    }

    /**
     * 정책 생성 도메인 설정: 기존 정책 참조가 필수이므로 전체 파이프라인 실행
     */
    @Override
    protected PipelineConfig getPipelineConfig() {
        return PipelineConfig.fullPipeline();
    }
}