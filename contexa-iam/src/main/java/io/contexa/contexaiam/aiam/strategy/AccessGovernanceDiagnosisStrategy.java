package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.accessGovernance.AccessGovernanceLab;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.request.AccessGovernanceRequest;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

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
        
        return PipelineConfig.fullPipeline();
    }
} 