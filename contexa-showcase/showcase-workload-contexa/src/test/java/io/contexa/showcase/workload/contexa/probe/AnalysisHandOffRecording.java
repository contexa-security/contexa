package io.contexa.showcase.workload.contexa.probe;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Replaces the hand-off to LLM analysis for the connection contract probes. They check the request plumbing and
 * the enforcement responses; real analysis is measured by LiveDecisionMeasurementTest and on the running stack.
 */
@TestConfiguration(proxyBeanMethods = false)
class AnalysisHandOffRecording {

    @Bean
    AnalysisHandOffRecorder securityEventPublisher() {
        return new AnalysisHandOffRecorder();
    }

    /** Events the engine handed to analysis (only while the user's action is PENDING_ANALYSIS). */
    static class AnalysisHandOffRecorder implements SecurityEventPublisher {

        private final ConcurrentLinkedQueue<ZeroTrustSpringEvent> handedOff = new ConcurrentLinkedQueue<>();

        @Override
        public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
            handedOff.add(event);
        }

        boolean handedOff(String requestId) {
            return handedOff.stream().anyMatch(event -> Objects.equals(requestId, event.getPayload().get("requestId")));
        }
    }
}
