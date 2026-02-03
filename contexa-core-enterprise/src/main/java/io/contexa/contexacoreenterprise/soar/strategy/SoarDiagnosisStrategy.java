package io.contexa.contexacoreenterprise.soar.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Slf4j
public class SoarDiagnosisStrategy extends AbstractAIStrategy<SoarContext, SoarResponse> {

    DiagnosisType diagnosisType = new DiagnosisType("soar");

    private static final int PRIORITY = 10; 
    private static final boolean SUPPORTS_STREAMING = true;

    public SoarDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
            }

    @Override
    public DiagnosisType getSupportedType() {
        return diagnosisType;
    }

    @Override
    public int getPriority() {
        return PRIORITY;
    }

    @Override
    public boolean supportsStreaming() {
        return SUPPORTS_STREAMING;
    }

    @Override
    protected void validateRequest(AIRequest<SoarContext> request) throws DiagnosisException {

        if (request.getContext() == null) {
            throw new DiagnosisException(
                    diagnosisType.name(),
                    "INVALID_CONTEXT",
                    "SoarContext가 누락되었습니다"
            );
        }

        SoarContext context = request.getContext();

        if (context.getSessionId() == null || context.getSessionId().isEmpty()) {
            throw new DiagnosisException(
                    diagnosisType.name(),
                    "INVALID_SESSION",
                    "세션 ID가 누락되었습니다"
            );
        }

        if (context.getOriginalQuery() == null || context.getOriginalQuery().trim().isEmpty()) {
            throw new DiagnosisException(
                    diagnosisType.name(),
                    "INVALID_QUERY",
                    "질의가 비어있습니다"
            );
        }

        if (context.getOrganizationId() == null || context.getOrganizationId().isEmpty()) {
            throw new DiagnosisException(
                    diagnosisType.name(),
                    "INVALID_ORGANIZATION",
                    "조직 ID가 누락되었습니다"
            );
        }

            }

    @Override
    protected Class<?> getLabType() {
        
        return SoarLabImpl.class;
    }

    @Override
    protected Object convertLabRequest(AIRequest<SoarContext> request) throws DiagnosisException {
        return request;
    }

    @Override
    protected SoarResponse processLabExecution(Object lab, Object labRequest, AIRequest<SoarContext> request)
            throws Exception {
        
        if (!(lab instanceof SoarLabImpl)) {
            throw new DiagnosisException(
                    diagnosisType.name(),
                    "INVALID_LAB",
                    "잘못된 Lab 타입: " + lab.getClass().getName()
            );
        }

        if (!(labRequest instanceof SoarRequest)) {
            throw new DiagnosisException(
                    diagnosisType.name(),
                    "INVALID_REQUEST",
                    "잘못된 요청 타입: " + labRequest.getClass().getName()
            );
        }

        SoarLabImpl soarLab = (SoarLabImpl) lab;
        SoarRequest soarRequest = (SoarRequest) labRequest;

        SoarResponse response = soarLab.process(soarRequest);

        updateContext(request.getContext(), response);

                return response;
    }

    @Override
    protected Mono<SoarResponse> processLabExecutionAsync(Object lab, Object labRequest,
                                                          AIRequest<SoarContext> originRequest) {

        AILab<SoarRequest, SoarResponse> soarLab = (SoarLabImpl) lab;
        SoarRequest soarRequest = (SoarRequest) labRequest;

                return soarLab.processAsync(soarRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest,
                                                     AIRequest<SoarContext> request) {
        AILab<SoarRequest, SoarResponse> soarLab = (SoarLabImpl) lab;
        SoarRequest soarRequest = (SoarRequest) labRequest;

                return soarLab.processStream(soarRequest);
    }

    private void updateContext(SoarContext context, SoarResponse response) {
        
        if (response.getAnalysisResult() != null) {
            context.addConversationEntry("assistant", response.getAnalysisResult());
        }

        if (response.getSessionState() != null) {
            context.setSessionState(response.getSessionState());
        }

        context.setLastActivity(LocalDateTime.now());

        if (response.getExecutedTools() != null && !response.getExecutedTools().isEmpty()) {
            response.getExecutedTools().forEach(tool ->
                    context.getApprovedTools().add(tool)
            );
        }
    }
}