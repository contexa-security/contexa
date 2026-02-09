package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class PolicyGenerationDiagnosisStrategy extends AbstractAIStrategy<PolicyContext, PolicyResponse> {

    public PolicyGenerationDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return new DiagnosisType("PolicyGeneration");
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

        String naturalLanguageQuery = request.getNaturalLanguageQuery();
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
    protected Object convertLabRequest(AIRequest<PolicyContext> request) {
        return request;
    }

    @Override
    protected PolicyResponse processLabExecution(Object lab, Object labRequest, AIRequest<PolicyContext> request) throws Exception {
        AILab<PolicyGenerationRequest, PolicyResponse> policyGenerationLab = (AdvancedPolicyGenerationLab) lab;
        PolicyGenerationRequest policyGenerationRequest = (PolicyGenerationRequest) labRequest;

        return policyGenerationLab.process(policyGenerationRequest);
    }

    @Override
    protected Mono<PolicyResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<PolicyContext> originRequest) {
        AILab<PolicyGenerationRequest, PolicyResponse> policyGenerationLab = (AdvancedPolicyGenerationLab) lab;
        PolicyGenerationRequest data = (PolicyGenerationRequest) labRequest;

        return policyGenerationLab.processAsync(data);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<PolicyContext> request) {
        AILab<PolicyGenerationRequest, PolicyResponse> policyGenerationLab = (AdvancedPolicyGenerationLab) lab;
        PolicyGenerationRequest policyGenerationRequest = (PolicyGenerationRequest) labRequest;

        return policyGenerationLab.processStream(policyGenerationRequest);
    }
}