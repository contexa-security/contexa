package io.contexa.contexaidentity.security.statemachine.monitoring;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents.ErrorEvent;
import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents.PerformanceAlertEvent;
import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents.StateChangeEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * MFA State Machine 모니터링
 * 이벤트 기반 메트릭 수집 및 성능 모니터링
 */
@Slf4j
public class MfaStateMachineMonitorServiceImpl implements MfaStateMachineMonitorService{

    private final MeterRegistry meterRegistry;
    private final ApplicationEventPublisher eventPublisher;

    public MfaStateMachineMonitorServiceImpl(
            MeterRegistry meterRegistry,
            ApplicationEventPublisher eventPublisher) {
        this.meterRegistry = meterRegistry;
        this.eventPublisher = eventPublisher;
    }

    // 메트릭 저장
    private final Map<String, Timer> transitionTimers = new ConcurrentHashMap<>();
    private final Map<MfaState, AtomicLong> stateDistribution = new ConcurrentHashMap<>();

    // 카운터
    private Counter totalTransitions;
    private Counter failedTransitions;
    private Gauge activeSessionsGauge;

    // 통계
    private final AtomicLong activeSessions = new AtomicLong(0);

    // 임계값
    private static final double ERROR_RATE_THRESHOLD = 0.1;
    private static final long SLOW_TRANSITION_THRESHOLD_MS = 1000;

    @PostConstruct
    public void init() {
        // 카운터 초기화
        totalTransitions = Counter.builder("mfa.transitions.total")
                .description("Total MFA state transitions")
                .register(meterRegistry);

        failedTransitions = Counter.builder("mfa.transitions.failed")
                .description("Failed MFA state transitions")
                .register(meterRegistry);

        // Gauge 초기화
        activeSessionsGauge = Gauge.builder("mfa.sessions.active", activeSessions, AtomicLong::get)
                .description("Active MFA sessions")
                .register(meterRegistry);

        // 상태별 분포 Gauge 초기화
        for (MfaState state : MfaState.values()) {
            AtomicLong counter = new AtomicLong(0);
            stateDistribution.put(state, counter);

            Gauge.builder("mfa.sessions.by.state", counter, AtomicLong::get)
                    .tag("state", state.name())
                    .description("Sessions in state " + state.name())
                    .register(meterRegistry);
        }
    }

    /**
     * 상태 변경 이벤트 처리
     */
    @EventListener
    @Async("mfaEventExecutor")
    public void handleStateChange(StateChangeEvent event) {
        try {
            // 전체 카운터 증가
            totalTransitions.increment();

            // 전이별 타이머 기록
            String transitionKey = event.getTransitionKey();
            Timer timer = transitionTimers.computeIfAbsent(transitionKey, k ->
                    Timer.builder("mfa.transition.duration")
                            .tag("from", event.getFromState() != null ? event.getFromState().name() : "INITIAL")
                            .tag("to", event.getToState().name())
                            .publishPercentiles(0.5, 0.95, 0.99)
                            .register(meterRegistry)
            );

            if (event.getDuration() != null) {
                timer.record(event.getDuration());

                // 느린 전이 감지
                if (event.getDuration().toMillis() > SLOW_TRANSITION_THRESHOLD_MS) {
                    publishPerformanceAlert(
                            PerformanceAlertEvent.AlertType.SLOW_TRANSITION,
                            String.format("Slow transition: %s (%d ms)", transitionKey, event.getDuration().toMillis()),
                            SLOW_TRANSITION_THRESHOLD_MS,
                            event.getDuration().toMillis(),
                            calculateSeverity(event.getDuration().toMillis(), SLOW_TRANSITION_THRESHOLD_MS)
                    );
                }
            }

            // 상태 분포 업데이트
            updateStateDistribution(event.getFromState(), event.getToState());

            // 세션 수 업데이트
            if (event.getToState() == MfaState.NONE) {
                activeSessions.incrementAndGet();
            } else if (event.getToState().isTerminal()) {
                activeSessions.decrementAndGet();
            }

            log.debug("State transition recorded: {}", transitionKey);

        } catch (Exception e) {
            log.error("Error handling state change event", e);
        }
    }

    /**
     * 에러 이벤트 처리
     */
    @EventListener
    @Async("mfaEventExecutor")
    public void handleError(ErrorEvent event) {
        try {
            // 실패 카운터 증가
            failedTransitions.increment();

            // 에러 타입별 카운터
            Counter.builder("mfa.errors")
                    .tag("type", event.getErrorType().name())
                    .tag("state", event.getCurrentState().name())
                    .register(meterRegistry)
                    .increment();

            // 에러율 확인
            checkErrorRate();

            log.error("MFA error recorded: {} in state {} for session {}",
                    event.getErrorType(), event.getCurrentState(), event.getSessionId());

        } catch (Exception e) {
            log.error("Error handling error event", e);
        }
    }

    /**
     * 성능 알림 발행
     */
    private void publishPerformanceAlert(PerformanceAlertEvent.AlertType type,
                                         String description,
                                         double threshold,
                                         double actualValue,
                                         PerformanceAlertEvent.Severity severity) {
        PerformanceAlertEvent alert = new PerformanceAlertEvent(
                this,  // source
                type,
                description,
                threshold,
                actualValue,
                severity
        );

        eventPublisher.publishEvent(alert);
    }

    /**
     * 상태 분포 업데이트
     */
    private void updateStateDistribution(MfaState fromState, MfaState toState) {
        if (fromState != null) {
            stateDistribution.get(fromState).decrementAndGet();
        }
        stateDistribution.get(toState).incrementAndGet();
    }

    /**
     * 에러율 확인 및 알림
     */
    private void checkErrorRate() {
        double total = totalTransitions.count();
        double failed = failedTransitions.count();

        if (total > 100) { // 최소 샘플 수
            double errorRate = failed / total;

            if (errorRate > ERROR_RATE_THRESHOLD) {
                publishPerformanceAlert(
                        PerformanceAlertEvent.AlertType.HIGH_ERROR_RATE,
                        String.format("High error rate: %.2f%%", errorRate * 100),
                        ERROR_RATE_THRESHOLD,
                        errorRate,
                        PerformanceAlertEvent.Severity.HIGH
                );
            }
        }
    }

    /**
     * 심각도 계산
     */
    private PerformanceAlertEvent.Severity calculateSeverity(double value, double threshold) {
        double ratio = value / threshold;
        if (ratio < 1.5) return PerformanceAlertEvent.Severity.LOW;
        if (ratio < 2.0) return PerformanceAlertEvent.Severity.MEDIUM;
        if (ratio < 3.0) return PerformanceAlertEvent.Severity.HIGH;
        return PerformanceAlertEvent.Severity.CRITICAL;
    }

    @Override
    public Map<String, Double> identifyBottlenecks() {
        return Map.of();
    }

    /**
     * 에러율 계산
     */
    private double calculateErrorRate() {
        double total = totalTransitions.count();
        if (total == 0) return 0;
        return failedTransitions.count() / total;
    }

    /**
     * 상태 분포 맵 생성
     */
    private Map<String, Long> getStateDistributionMap() {
        Map<String, Long> distribution = new ConcurrentHashMap<>();
        stateDistribution.forEach((state, count) -> {
            if (count.get() > 0) {
                distribution.put(state.name(), count.get());
            }
        });
        return distribution;
    }
}