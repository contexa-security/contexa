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

    private final Map<String, Timer> transitionTimers = new ConcurrentHashMap<>();
    private final Map<MfaState, AtomicLong> stateDistribution = new ConcurrentHashMap<>();

    private Counter totalTransitions;
    private Counter failedTransitions;
    private Gauge activeSessionsGauge;

    private final AtomicLong activeSessions = new AtomicLong(0);

    private static final double ERROR_RATE_THRESHOLD = 0.1;
    private static final long SLOW_TRANSITION_THRESHOLD_MS = 1000;

    @PostConstruct
    public void init() {
        
        totalTransitions = Counter.builder("mfa.transitions.total")
                .description("Total MFA state transitions")
                .register(meterRegistry);

        failedTransitions = Counter.builder("mfa.transitions.failed")
                .description("Failed MFA state transitions")
                .register(meterRegistry);

        activeSessionsGauge = Gauge.builder("mfa.sessions.active", activeSessions, AtomicLong::get)
                .description("Active MFA sessions")
                .register(meterRegistry);

        for (MfaState state : MfaState.values()) {
            AtomicLong counter = new AtomicLong(0);
            stateDistribution.put(state, counter);

            Gauge.builder("mfa.sessions.by.state", counter, AtomicLong::get)
                    .tag("state", state.name())
                    .description("Sessions in state " + state.name())
                    .register(meterRegistry);
        }
    }

    @EventListener
    @Async("mfaEventExecutor")
    public void handleStateChange(StateChangeEvent event) {
        try {
            
            totalTransitions.increment();

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

            updateStateDistribution(event.getFromState(), event.getToState());

            if (event.getToState() == MfaState.NONE) {
                activeSessions.incrementAndGet();
            } else if (event.getToState().isTerminal()) {
                activeSessions.decrementAndGet();
            }

        } catch (Exception e) {
            log.error("Error handling state change event", e);
        }
    }

    @EventListener
    @Async("mfaEventExecutor")
    public void handleError(ErrorEvent event) {
        try {
            
            failedTransitions.increment();

            Counter.builder("mfa.errors")
                    .tag("type", event.getErrorType().name())
                    .tag("state", event.getCurrentState().name())
                    .register(meterRegistry)
                    .increment();

            checkErrorRate();

            log.error("MFA error recorded: {} in state {} for session {}",
                    event.getErrorType(), event.getCurrentState(), event.getSessionId());

        } catch (Exception e) {
            log.error("Error handling error event", e);
        }
    }

    private void publishPerformanceAlert(PerformanceAlertEvent.AlertType type,
                                         String description,
                                         double threshold,
                                         double actualValue,
                                         PerformanceAlertEvent.Severity severity) {
        PerformanceAlertEvent alert = new PerformanceAlertEvent(
                this,  
                type,
                description,
                threshold,
                actualValue,
                severity
        );

        eventPublisher.publishEvent(alert);
    }

    private void updateStateDistribution(MfaState fromState, MfaState toState) {
        if (fromState != null) {
            stateDistribution.get(fromState).decrementAndGet();
        }
        stateDistribution.get(toState).incrementAndGet();
    }

    private void checkErrorRate() {
        double total = totalTransitions.count();
        double failed = failedTransitions.count();

        if (total > 100) { 
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

    private double calculateErrorRate() {
        double total = totalTransitions.count();
        if (total == 0) return 0;
        return failedTransitions.count() / total;
    }

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