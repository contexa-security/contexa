package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryLab;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class StudioQueryDiagnosisStrategy extends AbstractAIStrategy<StudioQueryContext, StudioQueryResponse> {

    public StudioQueryDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.STUDIO_QUERY;
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
            throw new DiagnosisException("STUDIO_QUERY", "NULL_REQUEST", "요청이 null입니다");
        }

        String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            throw new DiagnosisException("STUDIO_QUERY", "MISSING_NATURAL_LANGUAGE_QUERY",
                    "naturalLanguageQuery 파라미터가 필요합니다");
        }

        String organizationId = request.getParameter("organizationId", String.class);
        if (organizationId == null || organizationId.trim().isEmpty()) {
            log.warn("organizationId 파라미터가 없어 기본값을 사용합니다");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return StudioQueryLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<StudioQueryContext> request) {
        String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
        String organizationId = request.getParameter("organizationId", String.class);
        String userId = request.getParameter("userId", String.class);

        if (userId == null || userId.trim().isEmpty()) {
            throw new DiagnosisException("STUDIO_QUERY", "MISSING_USER_ID",
                    "userId 파라미터가 필요합니다. 정확한 사용자 인증이 필요합니다.");
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("organizationId", organizationId != null ? organizationId : "default-org");
        metadata.put("requestId", request.getRequestId());

        Boolean includeVisualization = request.getParameter("includeVisualization", Boolean.class);
        if (includeVisualization != null) {
            metadata.put("includeVisualization", includeVisualization);
        }

        Boolean includeRecommendations = request.getParameter("includeRecommendations", Boolean.class);
        if (includeRecommendations != null) {
            metadata.put("includeRecommendations", includeRecommendations);
        }

        String responseFormat = request.getParameter("responseFormat", String.class);
        if (responseFormat != null) {
            metadata.put("responseFormat", responseFormat);
        }

        String detailLevel = request.getParameter("detailLevel", String.class);
        if (detailLevel != null) {
            metadata.put("detailLevel", detailLevel);
        }

        String queryType = request.getParameter("queryType", String.class);
        if (queryType == null || queryType.trim().isEmpty()) {
            queryType = "GENERAL";
        }

        StudioQueryRequest studioQueryRequest = new StudioQueryRequest();
        studioQueryRequest.setQuery(naturalLanguageQuery);
        studioQueryRequest.setUserId(userId);
        studioQueryRequest.setMetadata(metadata);
        studioQueryRequest.setQueryType(queryType);
        studioQueryRequest.setTimestamp(LocalDateTime.now());

        return studioQueryRequest;
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
                    log.error("스트리밍 Studio Query 진단 전략 실행 실패 - 요청: {}", request.getRequestId(), error);
                });
    }

    @Override
    protected PipelineConfig getPipelineConfig() {

        return PipelineConfig.fullPipeline();
    }
}