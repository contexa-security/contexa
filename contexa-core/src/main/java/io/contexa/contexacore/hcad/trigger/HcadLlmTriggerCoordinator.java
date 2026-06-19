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
            return new TriggerLease(false, false, dedupKey);
        }
        if (stateRepository.isCoolingDown(dedupKey)) {
            return new TriggerLease(false, true, dedupKey);
        }
        Duration inFlightTtl = Duration.ofSeconds(hcadProperties.getPreTrigger().getInFlightTtlSeconds());
        if (!stateRepository.tryAcquireInFlight(dedupKey, inFlightTtl)) {
            return new TriggerLease(false, true, dedupKey);
        }
        if (!tryAcquireRateLimit(report, dedupKey)) {
            stateRepository.releaseInFlight(dedupKey);
            return new TriggerLease(false, false, dedupKey);
        }
        return new TriggerLease(true, false, dedupKey);
    }

    public void markCooldown(String dedupKey) {
        if (StringUtils.hasText(dedupKey)) {
            stateRepository.markCooldown(
                    dedupKey,
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getCooldownSeconds()));
        }
    }

    public void releaseInFlight(String dedupKey) {
        if (StringUtils.hasText(dedupKey)) {
            stateRepository.releaseInFlight(dedupKey);
        }
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
        return PendingAnomalyKeyFactory.buildTriggerKey(
                report.userId(),
                report.contextBindingHash(),
                report.httpMethod(),
                report.requestPath(),
                stateSignature);
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

    public record TriggerLease(
            boolean acquired,
            boolean duplicateSuppressed,
            String dedupKey
    ) {
    }
}
