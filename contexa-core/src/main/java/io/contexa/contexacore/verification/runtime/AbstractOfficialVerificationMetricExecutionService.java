package io.contexa.contexacore.verification.runtime;

import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

@Transactional(transactionManager = "contexaTransactionManager")
public abstract class AbstractOfficialVerificationMetricExecutionService<R> {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE = new ParameterizedTypeReference<>() {
    };
    private static final TypeReference<Map<String, Object>> JSON_MAP = new TypeReference<>() {
    };
    private static final String BRIDGE_HEADER_PREFIX = "X-Contexa-Verification-Bridge-";

    protected final SecurityDecisionForwardingOutboxRepository decisionOutboxRepository;
    protected final PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository;
    protected final OfficialVerificationAnalysisEventStore analysisEventStore;
    protected final WebClient.Builder webClientBuilder;
    protected final ObjectMapper objectMapper;

    private final OfficialVerificationPerUserRunRepository<R> runRepository;
    private final AtomicInteger sequence = new AtomicInteger(0);
    private final String notFoundMetricCode;

    protected AbstractOfficialVerificationMetricExecutionService(
            String notFoundMetricCode,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper,
            Function<R, String> runIdExtractor,
            Function<R, String> startedAtExtractor
    ) {
        this.notFoundMetricCode = notFoundMetricCode;
        this.decisionOutboxRepository = decisionOutboxRepository;
        this.promptAuditOutboxRepository = promptAuditOutboxRepository;
        this.analysisEventStore = analysisEventStore;
        this.webClientBuilder = webClientBuilder;
        this.objectMapper = objectMapper;
        this.runRepository = new OfficialVerificationPerUserRunRepository<>(
                runIdExtractor,
                Comparator.comparing(startedAtExtractor).reversed()
        );
    }

    public boolean ready() {
        return true;
    }

    public synchronized List<R> listRuns(String userId) {
        return runRepository.list(userId);
    }

    public synchronized R findRun(String userId, String runId) {
        return runRepository.find(userId, runId, "Official " + notFoundMetricCode + " run not found: " + runId);
    }

    protected final synchronized void storeRun(String userId, R run) {
        runRepository.add(userId, run);
    }

    protected final synchronized int nextRunOrdinal(String userId) {
        return runRepository.size(userId) + 1;
    }

    protected final String nextMetricRequestId(String prefix) {
        return prefix + System.currentTimeMillis() + "-" + sequence.incrementAndGet();
    }

    protected final List<OfficialVerificationAnalysisEventStore.AnalysisEvent> pollEvents(String requestId, Duration timeout) {
        return OfficialVerificationRuntimePollingSupport.awaitEvents(requestId, timeout, analysisEventStore);
    }

    protected final SecurityDecisionForwardingOutboxRecord pollDecisionOutbox(String requestId, Duration timeout) {
        return OfficialVerificationRuntimePollingSupport.awaitDecisionOutbox(requestId, timeout, decisionOutboxRepository);
    }

    protected final PromptContextAuditForwardingOutboxRecord pollPromptAuditOutbox(String requestId, Duration timeout) {
        return OfficialVerificationRuntimePollingSupport.awaitPromptAuditOutbox(requestId, timeout, promptAuditOutboxRepository);
    }

    protected final Map<String, Object> invokeProbeRequest(
            HttpServletRequest request,
            String requestPath,
            Consumer<HttpHeaders> headerConfigurer
    ) {
        String baseUrl = resolveBaseUrl(request);
        WebClient client = webClientBuilder.baseUrl(baseUrl).build();
        Map<String, Object> payload = client.get()
                .uri(requestPath)
                .headers(headers -> {
                    if (headerConfigurer != null) {
                        headerConfigurer.accept(headers);
                    }
                })
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .block(Duration.ofSeconds(30));
        return payload != null ? payload : Map.of();
    }

    protected final Map<String, Object> parseJson(String payloadJson) {
        if (!StringUtils.hasText(payloadJson)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(payloadJson, JSON_MAP);
        } catch (Exception ignored) {
            return Map.of();
        }
    }

    protected final void copyHeader(HttpServletRequest request, HttpHeaders headers, String name) {
        if (request == null || headers == null || !StringUtils.hasText(name)) {
            return;
        }
        String value = request.getHeader(name);
        if (StringUtils.hasText(value)) {
            headers.set(name, value);
        }
    }

    protected final void copyVerificationBridgeHeaders(HttpServletRequest request, HttpHeaders headers) {
        if (request == null || headers == null) {
            return;
        }
        var names = request.getHeaderNames();
        if (names == null) {
            return;
        }
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (!StringUtils.hasText(name) || !name.startsWith(BRIDGE_HEADER_PREFIX)) {
                continue;
            }
            String value = request.getHeader(name);
            if (StringUtils.hasText(value)) {
                headers.set(name, value);
            }
        }
    }
    protected final String resolveBaseUrl(HttpServletRequest request) {
        if (request == null) {
            return "http://localhost:10000";
        }
        String scheme = StringUtils.hasText(request.getScheme()) ? request.getScheme() : "http";
        String host = StringUtils.hasText(request.getServerName()) ? request.getServerName() : "localhost";
        int port = request.getServerPort();
        boolean defaultPort = ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);
        return defaultPort ? scheme + "://" + host : scheme + "://" + host + ":" + port;
    }

    protected final OfficialVerificationReplayPathSupport.ReplayTarget resolveStandardReplayTarget(
            String endpointKey,
            String resourceId,
            String requestPath,
            List<String> allowedEndpointKeys
    ) {
        return OfficialVerificationReplayPathSupport.resolveProbeTarget(endpointKey, resourceId, requestPath, allowedEndpointKeys);
    }

    protected final OfficialVerificationReplayPathSupport.ReplayTarget retargetStandardReplayTarget(
            String endpointKey,
            String resourceId,
            String requestPath,
            List<String> allowedEndpointKeys
    ) {
        return OfficialVerificationReplayPathSupport.retargetProbeTarget(endpointKey, resourceId, requestPath, allowedEndpointKeys);
    }

    protected final OfficialVerificationReplayPathSupport.ReplayTarget parseStandardReplayTarget(
            String requestPath,
            List<String> allowedEndpointKeys
    ) {
        return OfficialVerificationReplayPathSupport.parseProbeTarget(requestPath, allowedEndpointKeys);
    }

    protected final String defaultEndpointLabel(String endpointKey) {
        String normalized = StringUtils.hasText(endpointKey) ? endpointKey.trim().toLowerCase(Locale.ROOT) : "normal";
        return switch (normalized) {
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        };
    }
}

