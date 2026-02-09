package io.contexa.contexacore.std.pipeline;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.domain.SessionState;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import io.contexa.contexacore.std.strategy.AIStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class PipelineOrchestrator {

    private final List<PipelineExecutor> executors;
    private final Map<String, AIStrategy<?, ?>> strategyMap;

    @Autowired
    public PipelineOrchestrator(List<PipelineExecutor> executors,
                                List<AIStrategy<?, ?>> strategies) {
        this.executors = executors.stream()
                .sorted((a, b) -> Integer.compare(a.getPriority(), b.getPriority()))
                .toList();

        this.strategyMap = new ConcurrentHashMap<>();
        for (AIStrategy<?, ?> strategy : strategies) {
            strategyMap.put(strategy.getSupportedType().name(), strategy);
        }
    }

    public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            Class<R> responseType) {
        return execute(request, null, responseType);
    }

    public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration config,
            Class<R> responseType) {

        return Mono.fromCallable(() -> config)
                .flatMap(finalConfig -> selectExecutor(request, finalConfig)
                        .flatMap(executor -> executor.execute(request, finalConfig, responseType))
                )
                .doOnError(error ->
                        log.error("[Orchestrator] Pipeline failed: {} - {}",
                                request.getRequestId(), error.getMessage(), error))
                .onErrorResume(error -> createFallbackResponse(request, responseType, error));
    }

    public <T extends DomainContext> Flux<String> executeStream(AIRequest<T> request) {
        return executeStream(request, null);
    }

    public <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request,
            PipelineConfiguration config) {

        return selectExecutor(request, config)
                .flatMapMany(executor -> executor.executeStream(request, config))
                .doOnError(error ->
                        log.error("[Orchestrator] Streaming failed: {} - {}",
                                request.getRequestId(), error.getMessage(), error))
                .onErrorResume(error -> Flux.just("ERROR: " + error.getMessage()));
    }

    private <T extends DomainContext> Mono<PipelineExecutor> selectExecutor(
            AIRequest<T> request,
            PipelineConfiguration configuration) {

        boolean streamingRequired = configuration.isEnableStreaming();

        Optional<PipelineExecutor> selectedExecutor = executors.stream()
                .filter(executor -> executor.supportsConfiguration(configuration))
                .filter(executor -> executor.supportsStreaming() == streamingRequired)
                .findFirst();

        if (selectedExecutor.isPresent()) {
            return Mono.just(selectedExecutor.get());
        }

        Optional<PipelineExecutor> fallbackExecutor = executors.stream()
                .filter(executor -> executor.supportsConfiguration(configuration))
                .findFirst();

        return fallbackExecutor.map(Mono::just).orElseGet(() -> Mono.error(new IllegalStateException(
                "No PipelineExecutor found that supports configuration: " + configuration.getSteps())));

    }

    private <T extends DomainContext, R extends AIResponse> Mono<R> createFallbackResponse(
            AIRequest<T> request,
            Class<R> responseType,
            Throwable error) {

        log.error("[Orchestrator] Pipeline execution failed, creating fallback response: {} - {}",
                request.getRequestId(), error.getMessage(), error);

        try {
            R response;

            if (responseType.equals(SoarResponse.class)) {
                response = (R) createSoarFallbackResponse(error);
            } else {
                response = createGenericFallbackResponse(responseType, error);
            }

            return Mono.just(response);

        } catch (Exception e) {
            log.error("[Orchestrator] Exception occurred while creating fallback response", e);
            return Mono.error(new RuntimeException(
                    "Failed to create fallback response for " + responseType.getSimpleName() + ": " + e.getMessage(), e));
        }
    }

    private SoarResponse createSoarFallbackResponse(Throwable error) {
        SoarResponse soarResponse = new SoarResponse();

        soarResponse.withError("Pipeline execution failed: " + error.getMessage())
                .withMetadata("errorType", error.getClass().getSimpleName())
                .withMetadata("timestamp", System.currentTimeMillis());

        soarResponse.setAnalysisResult("Failed to complete SOAR analysis due to pipeline error: " + error.getMessage());
        soarResponse.setSummary("Pipeline execution failed");
        soarResponse.setRecommendations(List.of(
                "Review pipeline configuration",
                "Check model availability and API keys",
                "Verify context retrieval settings",
                "Retry the operation"
        ));
        soarResponse.setSessionState(SessionState.ERROR);
        soarResponse.setExecutedTools(List.of());

        return soarResponse;
    }

    private <R extends AIResponse> R createGenericFallbackResponse(
            Class<R> responseType,
            Throwable error) throws Exception {

        R response = createResponseInstance(responseType);

        response.withError("Pipeline execution failed: " + error.getMessage())
                .withMetadata("errorType", error.getClass().getSimpleName())
                .withMetadata("timestamp", System.currentTimeMillis());

        return response;
    }

    private <R extends AIResponse> R createResponseInstance(Class<R> responseType) throws Exception {
        try {
            return responseType.getDeclaredConstructor(String.class, AIResponse.ExecutionStatus.class).newInstance();
        } catch (NoSuchMethodException e) {
            try {
                return responseType.getDeclaredConstructor().newInstance();
            } catch (NoSuchMethodException ex) {
                throw new RuntimeException(
                        "No suitable constructor found for " + responseType.getSimpleName() +
                                ". Expected either () or (String, ExecutionStatus)", ex);
            }
        }
    }
}