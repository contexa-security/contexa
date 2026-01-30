package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.securityCopilot.SecurityCopilotLab;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotRequest;
import io.contexa.contexaiam.aiam.protocol.response.SecurityCopilotResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SecurityCopilotDiagnosisStrategy extends AbstractAIStrategy<SecurityCopilotContext, SecurityCopilotResponse> {

    public SecurityCopilotDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.SECURITY_COPILOT;
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
    protected void validateRequest(AIRequest<SecurityCopilotContext> request) throws DiagnosisException {
        if (request == null) {
            throw new DiagnosisException("SECURITY_COPILOT", "NULL_REQUEST", "요청이 null입니다");
        }

        String query = request.getParameter("securityQuery", String.class);
        if (query == null || query.trim().isEmpty()) {
            throw new DiagnosisException("SECURITY_COPILOT", "MISSING_SECURITY_QUERY",
                    "securityQuery 파라미터가 필요합니다");
        }

        String organizationId = request.getParameter("organizationId", String.class);
        if (organizationId == null || organizationId.trim().isEmpty()) {
            log.warn("organizationId 파라미터가 없어 기본값을 사용합니다");
        }

        String userId = request.getParameter("userId", String.class);
        if (userId == null || userId.trim().isEmpty()) {
            throw new DiagnosisException("SECURITY_COPILOT", "MISSING_USER_ID",
                    "userId 파라미터가 필요합니다. 정확한 사용자 인증이 필요합니다.");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return SecurityCopilotLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<SecurityCopilotContext> request) {
        String query = request.getParameter("securityQuery", String.class);
        String organizationId = request.getParameter("organizationId", String.class);
        String userId = request.getParameter("userId", String.class);

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("organizationId", organizationId != null ? organizationId : "default-org");
        metadata.put("requestId", request.getRequestId());
        metadata.put("timestamp", LocalDateTime.now().toString());

        String analysisScope = request.getParameter("analysisScope", String.class);
        if (analysisScope != null) {
            metadata.put("analysisScope", analysisScope);
        }

        Boolean includeRecommendations = request.getParameter("includeRecommendations", Boolean.class);
        if (includeRecommendations != null) {
            metadata.put("includeRecommendations", includeRecommendations);
        }

        Boolean includeComplianceCheck = request.getParameter("includeComplianceCheck", Boolean.class);
        if (includeComplianceCheck != null) {
            metadata.put("includeComplianceCheck", includeComplianceCheck);
        }

        String priority = request.getParameter("priority", String.class);
        if (priority != null) {
            metadata.put("priority", priority);
        }
        SecurityCopilotRequest securityCopilotRequest = new SecurityCopilotRequest();
        securityCopilotRequest.setSecurityQuery(query);
        securityCopilotRequest.setUserId(userId);
        securityCopilotRequest.setMetadata(metadata);
        return securityCopilotRequest;
    }

    @Override
    protected SecurityCopilotResponse processLabExecution(Object lab, Object labRequest, AIRequest<SecurityCopilotContext> request) throws Exception {
        AILab<SecurityCopilotRequest, SecurityCopilotResponse> securityCopilotLab = (SecurityCopilotLab) lab;
        SecurityCopilotRequest securityCopilotRequest = (SecurityCopilotRequest) labRequest;

                return securityCopilotLab.process(securityCopilotRequest);
    }

    @Override
    protected Mono<SecurityCopilotResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<SecurityCopilotContext> originRequest) {
        AILab<SecurityCopilotRequest, SecurityCopilotResponse> securityCopilotLab = (SecurityCopilotLab) lab;
        SecurityCopilotRequest securityCopilotRequest = (SecurityCopilotRequest) labRequest;

                return securityCopilotLab.processAsync(securityCopilotRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<SecurityCopilotContext> request) {
        AILab<SecurityCopilotRequest, SecurityCopilotResponse> securityCopilotLab = (SecurityCopilotLab) lab;
        SecurityCopilotRequest securityCopilotRequest = (SecurityCopilotRequest) labRequest;

                return securityCopilotLab.processStream(securityCopilotRequest);
    }

    @Override
    protected PipelineConfig getPipelineConfig() {
        
        return PipelineConfig.fullPipeline();
    }
}