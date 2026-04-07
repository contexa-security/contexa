package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import java.time.Duration;

@Slf4j
public class PendingAnomalyTriggerOrchestrator {

    private final PendingAnomalyEligibilityGate eligibilityGate;
    private final PendingAnomalyEvidenceCheckService evidenceCheckService;
    private final PendingAnomalyEventTriggerService eventTriggerService;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final HcadProperties hcadProperties;

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        this.eligibilityGate = eligibilityGate;
        this.evidenceCheckService = evidenceCheckService;
        this.eventTriggerService = eventTriggerService;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.hcadProperties = hcadProperties;
    }

    public void maybeTrigger(HttpServletRequest request, Authentication authentication) {
        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(request, authentication);
        if (eligibility == null) {
            return;
        }

        PendingAnomalyEvidenceReport report = evidenceCheckService.evaluate(request, eligibility);
        if (!report.shouldTrigger()) {
            analysisTriggerStateRepository.markNegative(
                    eligibility.baseKey(),
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getNegativeCacheSeconds()));
            return;
        }

        String dedupKey = eligibility.baseKey();
        if (analysisTriggerStateRepository.isCoolingDown(dedupKey)) {
            return;
        }

        Duration inFlightTtl = Duration.ofSeconds(hcadProperties.getPreTrigger().getInFlightTtlSeconds());
        if (!analysisTriggerStateRepository.tryAcquireInFlight(dedupKey, inFlightTtl)) {
            return;
        }

        try {
            eventTriggerService.publish(request, report);
            analysisTriggerStateRepository.markCooldown(
                    dedupKey,
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getCooldownSeconds()));
        } catch (RuntimeException ex) {
            analysisTriggerStateRepository.releaseInFlight(dedupKey);
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to publish pre-protectable threat event", ex);
        }
    }
}
