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
import org.springframework.util.StringUtils;

import java.time.Duration;

public class HcadLlmTriggerCoordinator {

    private final AnalysisTriggerStateRepository stateRepository;
    private final HcadProperties hcadProperties;

    public HcadLlmTriggerCoordinator(
            AnalysisTriggerStateRepository stateRepository,
            HcadProperties hcadProperties) {
        this.stateRepository = stateRepository;
        this.hcadProperties = hcadProperties;
    }

    public TriggerLease tryAcquire(PendingAnomalyEvidenceReport report, String fallbackBaseKey) {
        String dedupKey = resolveDedupKey(report, fallbackBaseKey);
        if (!StringUtils.hasText(dedupKey)) {
            return new TriggerLease(false, false, dedupKey, null);
        }
        String escalationKey = resolveEscalationKey(report);
        Duration inFlightTtl = Duration.ofSeconds(hcadProperties.getPreTrigger().getInFlightTtlSeconds());
        if (StringUtils.hasText(escalationKey)) {
            if (stateRepository.isCoolingDown(escalationKey)) {
                return new TriggerLease(false, true, dedupKey, escalationKey);
            }
            if (!stateRepository.tryAcquireInFlight(escalationKey, inFlightTtl)) {
                return new TriggerLease(false, true, dedupKey, escalationKey);
            }
        }
        if (stateRepository.isCoolingDown(dedupKey)) {
            releaseEscalationInFlight(escalationKey);
            return new TriggerLease(false, true, dedupKey, escalationKey);
        }
        if (!stateRepository.tryAcquireInFlight(dedupKey, inFlightTtl)) {
            releaseEscalationInFlight(escalationKey);
            return new TriggerLease(false, true, dedupKey, escalationKey);
        }
        if (!tryAcquireRateLimit(report, dedupKey)) {
            stateRepository.releaseInFlight(dedupKey);
            releaseEscalationInFlight(escalationKey);
            return new TriggerLease(false, false, dedupKey, escalationKey);
        }
        return new TriggerLease(true, false, dedupKey, escalationKey);
    }

    public void markCooldown(String dedupKey) {
        if (StringUtils.hasText(dedupKey)) {
            stateRepository.markCooldown(
                    dedupKey,
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getCooldownSeconds()));
        }
    }

    public void markCooldown(TriggerLease triggerLease) {
        if (triggerLease == null) {
            return;
        }
        markCooldown(triggerLease.dedupKey());
        if (StringUtils.hasText(triggerLease.escalationKey())) {
            stateRepository.markCooldown(
                    triggerLease.escalationKey(),
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getEscalationCooldownSeconds()));
        }
    }

    public void rememberEvaluation(TriggerLease triggerLease, String evaluationId) {
        if (triggerLease == null || !StringUtils.hasText(evaluationId)) {
            return;
        }
        Duration ttl = activeEvaluationTtl();
        if (StringUtils.hasText(triggerLease.dedupKey())) {
            stateRepository.rememberActiveEvaluation(triggerLease.dedupKey(), evaluationId, ttl);
        }
        if (StringUtils.hasText(triggerLease.escalationKey())) {
            stateRepository.rememberActiveEvaluation(triggerLease.escalationKey(), evaluationId, ttl);
        }
    }

    public String findActiveEvaluation(TriggerLease triggerLease) {
        if (triggerLease == null) {
            return null;
        }
        String escalationEvaluation = findActiveEvaluation(triggerLease.escalationKey());
        if (StringUtils.hasText(escalationEvaluation)) {
            return escalationEvaluation;
        }
        return findActiveEvaluation(triggerLease.dedupKey());
    }

    public String findActiveEvaluation(String stateKey) {
        if (!StringUtils.hasText(stateKey)) {
            return null;
        }
        return stateRepository.findActiveEvaluation(stateKey);
    }

    public void releaseInFlight(String dedupKey) {
        if (StringUtils.hasText(dedupKey)) {
            stateRepository.releaseInFlight(dedupKey);
        }
    }

    public void releaseInFlight(TriggerLease triggerLease) {
        if (triggerLease == null) {
            return;
        }
        releaseInFlight(triggerLease.dedupKey());
        releaseEscalationInFlight(triggerLease.escalationKey());
    }

    public String resolveDedupKey(PendingAnomalyEvidenceReport report, String fallbackBaseKey) {
        if (report == null) {
            return fallbackBaseKey;
        }
        if (StringUtils.hasText(report.triggerStateKey())) {
            return report.triggerStateKey();
        }
        String stateSignature = StringUtils.hasText(report.riskSignature())
                ? report.riskSignature()
                : report.requestId();
        if (!StringUtils.hasText(stateSignature)) {
            return fallbackBaseKey;
        }
        String actorSessionKey = report.rawSignalSnapshot() == null
                ? null
                : String.valueOf(report.rawSignalSnapshot().getOrDefault("actorSessionKey", ""));
        if (StringUtils.hasText(actorSessionKey)) {
            return PendingAnomalyKeyFactory.buildActorSessionDedupKey(actorSessionKey, stateSignature);
        }
        return PendingAnomalyKeyFactory.buildDedupKey(report.userId(), report.contextBindingHash(), stateSignature);
    }

    public String resolveEscalationKey(PendingAnomalyEvidenceReport report) {
        if (report == null) {
            return null;
        }
        String anchorSignature = PendingAnomalyKeyFactory.buildTrustedAnchorSignature(report.anchorSignals());
        if (!StringUtils.hasText(anchorSignature)) {
            return null;
        }
        String actorSessionKey = report.rawSignalSnapshot() == null
                ? null
                : String.valueOf(report.rawSignalSnapshot().getOrDefault("actorSessionKey", ""));
        if (!StringUtils.hasText(actorSessionKey)) {
            actorSessionKey = PendingAnomalyKeyFactory.buildBaseKey(report.userId(), report.contextBindingHash());
        }
        return PendingAnomalyKeyFactory.buildEscalationKey(actorSessionKey, anchorSignature);
    }

    private boolean tryAcquireRateLimit(PendingAnomalyEvidenceReport report, String dedupKey) {
        HcadProperties.PreTriggerSettings.LlmRateLimitSettings rate =
                hcadProperties.getPreTrigger().getLlmRateLimit();
        if (rate == null || !rate.isEnabled()) {
            return true;
        }
        String rateKey = rateKey(report, dedupKey, rate.getScope());
        if (!StringUtils.hasText(rateKey)) {
            return false;
        }
        return stateRepository.tryAcquireRateLimit(
                rateKey,
                Duration.ofSeconds(rate.getWindowSeconds()),
                rate.getMaxTriggersPerWindow());
    }

    private String rateKey(PendingAnomalyEvidenceReport report, String dedupKey, String scope) {
        String normalizedScope = StringUtils.hasText(scope) ? scope.trim().toUpperCase() : "GLOBAL";
        if ("USER".equals(normalizedScope) && report != null && StringUtils.hasText(report.userId())) {
            return "user:" + report.userId();
        }
        if ("RESOURCE".equals(normalizedScope) && report != null
                && StringUtils.hasText(report.httpMethod()) && StringUtils.hasText(report.requestPath())) {
            return "resource:" + report.httpMethod().toUpperCase() + ":" + report.requestPath();
        }
        if ("REQUEST".equals(normalizedScope) && StringUtils.hasText(dedupKey)) {
            return "request:" + dedupKey;
        }
        return "global";
    }

    private void releaseEscalationInFlight(String escalationKey) {
        if (StringUtils.hasText(escalationKey)) {
            stateRepository.releaseInFlight(escalationKey);
        }
    }

    private Duration activeEvaluationTtl() {
        long cooldown = Math.max(1L, hcadProperties.getPreTrigger().getCooldownSeconds());
        long escalationCooldown = Math.max(cooldown, hcadProperties.getPreTrigger().getEscalationCooldownSeconds());
        long inFlight = Math.max(escalationCooldown, hcadProperties.getPreTrigger().getInFlightTtlSeconds());
        return Duration.ofSeconds(inFlight);
    }

    public record TriggerLease(
            boolean acquired,
            boolean duplicateSuppressed,
            String dedupKey,
            String escalationKey
    ) {
    }
}
