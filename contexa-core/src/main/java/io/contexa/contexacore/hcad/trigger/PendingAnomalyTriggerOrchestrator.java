/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

        boolean success = false;
        try {
            eventTriggerService.publish(request, report);
            analysisTriggerStateRepository.markCooldown(
                    dedupKey,
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getCooldownSeconds()));
            success = true;
        } catch (Exception ex) {
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to publish pre-protectable threat event", ex);
        } finally {
            if (!success) {
                analysisTriggerStateRepository.releaseInFlight(dedupKey);
            }
        }
    }
}
