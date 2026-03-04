package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryLab;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class StudioQueryDiagnosisStrategy extends AbstractAIStrategy<StudioQueryContext, StudioQueryResponse> {

    public StudioQueryDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return new DiagnosisType("StudioQuery");
    }

    @Override
    public int getPriority() {
        return 10;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected void validateRequest(AIRequest<StudioQueryContext> request) throws DiagnosisException {
        if (request == null) {
            throw new DiagnosisException("STUDIO_QUERY", "NULL_REQUEST", "Request is null");
        }

        StudioQueryContext context = request.getContext();
        if (context == null) {
            throw new DiagnosisException("STUDIO_QUERY", "NULL_CONTEXT", "Context is null");
        }

        String organizationId = context.getOrganizationId();
        if (organizationId == null || organizationId.trim().isEmpty()) {
            log.error("organizationId is missing, using default value");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return StudioQueryLab.class;
    }

    @Override
    protected Object convertLabRequest(AIRequest<StudioQueryContext> request) {
        return request;
    }

    @Override
    protected StudioQueryResponse processLabExecution(Object lab, Object labRequest, AIRequest<StudioQueryContext> request) throws Exception {
        AILab<StudioQueryRequest, StudioQueryResponse> studioQueryLab = (StudioQueryLab) lab;
        StudioQueryRequest studioQueryRequest = (StudioQueryRequest) labRequest;

        return studioQueryLab.process(studioQueryRequest);
    }

    @Override
    protected Mono<StudioQueryResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<StudioQueryContext> originRequest) {
        AILab<StudioQueryRequest, StudioQueryResponse> studioQueryLab = (StudioQueryLab) lab;
        StudioQueryRequest studioQueryRequest = (StudioQueryRequest) labRequest;

        return studioQueryLab.processAsync(studioQueryRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<StudioQueryContext> request) {
        AILab<StudioQueryRequest, StudioQueryResponse> studioQueryLab = (StudioQueryLab) lab;
        StudioQueryRequest studioQueryRequest = (StudioQueryRequest) labRequest;

        return studioQueryLab.processStream(studioQueryRequest)
                .doOnError(error -> {
                    log.error("Streaming Studio Query diagnosis strategy execution failed - request: {}", request.getRequestId(), error);
                });
    }
}