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

/**
 * 모든 Advisor의 기본 추상 클래스
 * 
 * 공통 기능을 제공하며 도메인별 Advisor 구현의 기반이 됩니다.
 * - 로깅 및 메트릭 수집
 * - 컨텍스트 관리
 * - 에러 처리
 * - 체인 실행 지원
 */
@Slf4j
@Getter
public abstract class BaseAdvisor implements CallAdvisor, StreamAdvisor {

    /**
     * OpenTelemetry Tracer
     */
    protected final Tracer tracer;

    /**
     * Advisor가 속한 도메인 (예: SOAR, IAM, COMPLIANCE)
     */
    protected final String domain;

    /**
     * Advisor 이름 (도메인 내에서 고유)
     */
    protected final String name;

    /**
     * 실행 순서 (낮을수록 먼저 실행)
     */
    protected final int order;

    /**
     * Advisor 활성화 여부
     */
    protected boolean enabled = true;

    /**
     * 메트릭 수집용 카운터
     */
    private final Map<String, Long> metrics = new ConcurrentHashMap<>();

    protected BaseAdvisor(Tracer tracer, String domain, String name, int order) {
        this.tracer = tracer;
        this.domain = domain;
        this.name = name;
        this.order = order;
    }
    
    /**
     * Advisor 전체 이름 (도메인.이름)
     */
    @Override
    public String getName() {
        return String.format("%s.%s", domain, name);
    }
    
    /**
     * 실행 순서
     */
    @Override
    public int getOrder() {
        return order;
    }
    
    /**
     * 동기 호출 처리 (템플릿 메서드 패턴)
     */
    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        if (!enabled) {
            log.debug("Advisor {} is disabled, skipping", getName());
            return chain.nextCall(request);
        }

        long startTime = System.currentTimeMillis();
        String advisorKey = getName() + ".call";

        // OpenTelemetry Span 시작
        Span span = tracer.spanBuilder("advisor.adviseCall")
                .setAttribute("advisor.domain", domain)
                .setAttribute("advisor.name", name)
                .setAttribute("advisor.order", order)
                .setAttribute("advisor.fullname", getName())
                .startSpan();

        try (Scope scope = span.makeCurrent()) {
            // Pre-processing
            log.debug("[{}] Advisor 시작 - 요청 처리", getName());
            request = beforeCall(request);

            // 컨텍스트에 도메인 정보 추가
            enrichContext(request.context());

            // Chain execution
            ChatClientResponse response = chain.nextCall(request);

            // Post-processing
            response = afterCall(response, request);

            // 메트릭 기록
            long duration = System.currentTimeMillis() - startTime;
            recordMetric(advisorKey + ".success", 1);
            recordMetric(advisorKey + ".duration", duration);

            span.setAttribute("advisor.duration.ms", duration);
            span.setStatus(StatusCode.OK);

            log.debug("[{}] Advisor 완료 ({}ms)", getName(), duration);
            return response;

        } catch (AdvisorException e) {
            // Advisor 특정 예외 처리
            long duration = System.currentTimeMillis() - startTime;
            span.setAttribute("advisor.duration.ms", duration);
            span.recordException(e);
            span.setStatus(StatusCode.ERROR, e.getMessage());

            log.error("[{}] Advisor 처리 중 오류: {}", getName(), e.getMessage());
            recordMetric(advisorKey + ".error", 1);

            if (e.isBlocking()) {
                // 블로킹 오류인 경우 체인 중단
                return handleBlockingError(e, request);
            } else {
                // 논블로킹 오류인 경우 체인 계속
                return chain.nextCall(request);
            }

        } catch (Exception e) {
            // 일반 예외 처리
            log.error("[{}] 예상치 못한 오류", getName(), e);
            recordMetric(advisorKey + ".error", 1);
            
            // 오류 정보를 컨텍스트에 저장하고 체인 계속
            request.context().put(getName() + ".error", e.getMessage());
            return chain.nextCall(request);
        }
    }
    
    /**
     * 스트리밍 호출 처리 (템플릿 메서드 패턴)
     */
    @Override
    public Flux<ChatClientResponse> adviseStream(ChatClientRequest request, StreamAdvisorChain chain) {
        if (!enabled) {
            log.debug("Advisor {} is disabled, skipping stream", getName());
            return chain.nextStream(request);
        }
        
        long startTime = System.currentTimeMillis();
        String advisorKey = getName() + ".stream";
        
        try {
            // Pre-processing
            log.debug("[{}] Advisor 스트림 시작", getName());
            ChatClientRequest finalRequest = beforeStream(request);
            
            // 컨텍스트에 도메인 정보 추가
            enrichContext(finalRequest.context());
            
            // Chain execution
            Flux<ChatClientResponse> responses = chain.nextStream(finalRequest);
            
            // Post-processing with metrics
            return responses
                .doOnNext(response -> afterStream(response, finalRequest))
                .doOnComplete(() -> {
                    recordMetric(advisorKey + ".success", 1);
                    recordMetric(advisorKey + ".duration", System.currentTimeMillis() - startTime);
                    log.debug("[{}] Advisor 스트림 완료", getName());
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
    
    /**
     * 동기 호출 전처리 (서브클래스에서 구현)
     */
    protected abstract ChatClientRequest beforeCall(ChatClientRequest request);
    
    /**
     * 동기 호출 후처리 (서브클래스에서 구현)
     */
    protected abstract ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request);
    
    /**
     * 스트리밍 호출 전처리 (서브클래스에서 선택적 구현)
     */
    protected ChatClientRequest beforeStream(ChatClientRequest request) {
        // 기본적으로 동기 호출과 동일한 전처리
        return beforeCall(request);
    }
    
    /**
     * 스트리밍 호출 후처리 (서브클래스에서 선택적 구현)
     */
    protected void afterStream(ChatClientResponse response, ChatClientRequest request) {
        // 기본적으로 아무 작업 없음
    }
    
    /**
     * 컨텍스트에 도메인 정보 추가
     */
    protected void enrichContext(Map<String, Object> context) {
        context.put("advisor.domain", domain);
        context.put("advisor.name", getName());
        context.put("advisor.timestamp", System.currentTimeMillis());
    }
    
    /**
     * 블로킹 오류 처리
     * 
     * Spring AI 1.0에서는 ChatClientResponse를 직접 생성할 수 없으므로
     * AdvisorException을 통해 오류를 전파합니다.
     */
    protected ChatClientResponse handleBlockingError(AdvisorException e, ChatClientRequest request) {
        // 컨텍스트에 오류 정보 저장
        request.context().put("advisor.error", true);
        request.context().put("advisor.error.message", e.getMessage());
        request.context().put("advisor.error.domain", domain);
        request.context().put("advisor.blocked.by", getName());
        
        // AdvisorException을 다시 던져서 체인을 중단
        throw e;
    }
    
    /**
     * 메트릭 기록
     */
    protected void recordMetric(String key, long value) {
        metrics.merge(key, value, Long::sum);
    }
    
    /**
     * 메트릭 조회
     */
    public Map<String, Long> getMetrics() {
        return new ConcurrentHashMap<>(metrics);
    }
    
    /**
     * Advisor 활성화/비활성화
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        log.info("Advisor {} {}", getName(), enabled ? "enabled" : "disabled");
    }
    
    /**
     * Advisor 설정 검증
     */
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