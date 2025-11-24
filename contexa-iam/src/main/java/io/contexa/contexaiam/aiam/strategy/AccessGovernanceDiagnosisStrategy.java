package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics;
import io.contexa.contexacore.std.pipeline.condition.AlwaysExecuteCondition;
import io.contexa.contexaiam.aiam.labs.accessGovernance.AccessGovernanceLab;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.request.AccessGovernanceRequest;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 권한 거버넌스 분석 전략
 *
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하는 AI 전략
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 *
 * 전략 목표:
 * - 권한 배분 최적화: "우리 시스템의 권한 배분 상태가 전반적으로 건강하고 최적화되어 있는가?"
 * - 과도한 권한 탐지: "과도한 권한을 가진 사용자를 찾아줘"
 * - 미사용 권한 식별: "사용하지 않는 권한이 있나?"
 * - 권한 상속 경로 추적: "권한 상속 구조가 올바른가?"
 * - 업무 분리 위반 검사: "업무 분리 원칙에 위반되는 권한 배분이 있는가?"
 */
@Slf4j
public class AccessGovernanceDiagnosisStrategy extends AbstractAIStrategy<AccessGovernanceContext, AccessGovernanceResponse> {

    @Autowired
    public AccessGovernanceDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.ACCESS_GOVERNANCE;
    }

    @Override
    public int getPriority() {
        return 5;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected void validateRequest(AIRequest<AccessGovernanceContext> request) throws DiagnosisException {
        if (request.getContext() == null) {
            throw new DiagnosisException("MISSING_CONTEXT", "CONTEXT_NULL", "AccessGovernanceContext is required.");
        }
        if (request.getContext().getAuditScope() == null || request.getContext().getAuditScope().isEmpty()) {
            throw new DiagnosisException("MISSING_AUDIT_SCOPE", "AUDIT_SCOPE_NULL", "Audit scope is required for access governance analysis.");
        }
        if (request.getContext().getAnalysisType() == null || request.getContext().getAnalysisType().isEmpty()) {
            throw new DiagnosisException("MISSING_ANALYSIS_TYPE", "ANALYSIS_TYPE_NULL", "Analysis type is required for access governance analysis.");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return AccessGovernanceLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<AccessGovernanceContext> request) {
        return request;
    }

    @Override
    protected AccessGovernanceResponse processLabExecution(Object lab, Object labRequest, AIRequest<AccessGovernanceContext> request) throws Exception {
        AILab<AccessGovernanceRequest, AccessGovernanceResponse> accessGovernanceLab = (AccessGovernanceLab) lab;
        AccessGovernanceRequest accessGovernanceRequest = (AccessGovernanceRequest) labRequest;
        return accessGovernanceLab.process(accessGovernanceRequest);
    }

    @Override
    protected Mono<AccessGovernanceResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<AccessGovernanceContext> originRequest) {
        AILab<AccessGovernanceRequest, AccessGovernanceResponse> accessGovernanceLab = (AccessGovernanceLab) lab;
        AccessGovernanceRequest accessGovernanceRequest = (AccessGovernanceRequest) labRequest;
        return accessGovernanceLab.processAsync(accessGovernanceRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<AccessGovernanceContext> request) {
        AILab<AccessGovernanceRequest, AccessGovernanceResponse> accessGovernanceLab = (AccessGovernanceLab) lab;
        AccessGovernanceRequest accessGovernanceRequest = (AccessGovernanceRequest) labRequest;
        return accessGovernanceLab.processStream(accessGovernanceRequest);
    }

    @Override
    protected PipelineConfig getPipelineConfig() {
        // 거버넌스 분석은 전체 시스템 스캔과 정확한 분석이 필요하므로 전체 파이프라인 실행
        return PipelineConfig.fullPipeline();
    }
} 