package io.contexa.contexacore.std.advisor.core;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisor;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisorChain;
import reactor.core.publisher.Flux;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Getter
public abstract class BaseAdvisor implements CallAdvisor, StreamAdvisor {

    protected final Tracer tracer;

    protected final String domain;

    protected final String name;

    protected final int order;

    protected boolean enabled = true;

    private final Map<String, Long> metrics = new ConcurrentHashMap<>();

    protected BaseAdvisor(Tracer tracer, String domain, String name, int order) {
        this.tracer = tracer;
        this.domain = domain;
        this.name = name;
        this.order = order;
    }

    @Override
    public String getName() {
        return String.format("%s.%s", domain, name);
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        if (!enabled) {
            return chain.nextCall(request);
        }

        long startTime = System.currentTimeMillis();
        String advisorKey = getName() + ".call";

        Span span = tracer.spanBuilder("advisor.adviseCall")
                .setAttribute("advisor.domain", domain)
                .setAttribute("advisor.name", name)
                .setAttribute("advisor.order", order)
                .setAttribute("advisor.fullname", getName())
                .startSpan();

        try (Scope scope = span.makeCurrent()) {

            request = beforeCall(request);

            enrichContext(request.context());

            ChatClientResponse response = chain.nextCall(request);

            response = afterCall(response, request);

            long duration = System.currentTimeMillis() - startTime;
            recordMetric(advisorKey + ".success", 1);
            recordMetric(advisorKey + ".duration", duration);

            span.setAttribute("advisor.duration.ms", duration);
            span.setStatus(StatusCode.OK);

            return response;

        } catch (AdvisorException e) {

            long duration = System.currentTimeMillis() - startTime;
            span.setAttribute("advisor.duration.ms", duration);
            span.recordException(e);
            span.setStatus(StatusCode.ERROR, e.getMessage());

            log.error("[{}] Advisor 처리 중 오류: {}", getName(), e.getMessage());
            recordMetric(advisorKey + ".error", 1);

            if (e.isBlocking()) {

                return handleBlockingError(e, request);
            } else {

                return chain.nextCall(request);
            }

        } catch (Exception e) {

            log.error("[{}] 예상치 못한 오류", getName(), e);
            recordMetric(advisorKey + ".error", 1);

            request.context().put(getName() + ".error", e.getMessage());
            return chain.nextCall(request);
        }
    }

    @Override
    public Flux<ChatClientResponse> adviseStream(ChatClientRequest request, StreamAdvisorChain chain) {
        if (!enabled) {
            return chain.nextStream(request);
        }

        long startTime = System.currentTimeMillis();
        String advisorKey = getName() + ".stream";

        try {

            ChatClientRequest finalRequest = beforeStream(request);

            enrichContext(finalRequest.context());

            Flux<ChatClientResponse> responses = chain.nextStream(finalRequest);

            return responses
                    .doOnNext(response -> afterStream(response, finalRequest))
                    .doOnComplete(() -> {
                        recordMetric(advisorKey + ".success", 1);
                        recordMetric(advisorKey + ".duration", System.currentTimeMillis() - startTime);
                    })
                    .doOnError(error -> {
                        log.error("[{}] 스트림 오류", getName(), error);
                        recordMetric(advisorKey + ".error", 1);
                    });

        } catch (Exception e) {
            log.error("[{}] 스트림 시작 오류", getName(), e);
            recordMetric(advisorKey + ".error", 1);
            return chain.nextStream(request);
        }
    }

    protected abstract ChatClientRequest beforeCall(ChatClientRequest request);

    protected abstract ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request);

    protected ChatClientRequest beforeStream(ChatClientRequest request) {

        return beforeCall(request);
    }

    protected void afterStream(ChatClientResponse response, ChatClientRequest request) {

    }

    protected void enrichContext(Map<String, Object> context) {
        context.put("advisor.domain", domain);
        context.put("advisor.name", getName());
        context.put("advisor.timestamp", System.currentTimeMillis());
    }

    protected ChatClientResponse handleBlockingError(AdvisorException e, ChatClientRequest request) {

        request.context().put("advisor.error", true);
        request.context().put("advisor.error.message", e.getMessage());
        request.context().put("advisor.error.domain", domain);
        request.context().put("advisor.blocked.by", getName());

        throw e;
    }

    protected void recordMetric(String key, long value) {
        metrics.merge(key, value, Long::sum);
    }

    public Map<String, Long> getMetrics() {
        return new ConcurrentHashMap<>(metrics);
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean validate() {
        if (domain == null || domain.isEmpty()) {
            log.error("Domain is required for advisor");
            return false;
        }
        if (name == null || name.isEmpty()) {
            log.error("Name is required for advisor");
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return String.format("Advisor[%s, order=%d, enabled=%s]", getName(), order, enabled);
    }
}