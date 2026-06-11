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
package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;
import io.contexa.contexacore.domain.entity.ModelPerformanceTelemetryOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.ModelPerformanceTelemetryOutboxRepository;

import java.time.Clock;
import java.time.LocalDate;

public class ModelPerformanceTelemetryCollector implements LlmAnalysisEventObserver {

    private final ModelPerformanceTelemetryOutboxRepository repository;
    private final SaasForwardingProperties properties;
    private final Clock clock;

    public ModelPerformanceTelemetryCollector(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasForwardingProperties properties) {
        this(repository, properties, Clock.systemDefaultZone());
    }

    ModelPerformanceTelemetryCollector(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasForwardingProperties properties,
            Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getPerformanceTelemetry() != null
                && properties.getPerformanceTelemetry().isEnabled();
    }

    @Override
    public synchronized void onLayer1Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs) {
        if (!isEnabled()) {
            return;
        }
        ModelPerformanceTelemetryOutboxRecord record = currentRecord();
        record.recordLayer1("ESCALATE".equalsIgnoreCase(action), elapsedMs);
        repository.save(record);
    }

    @Override
    public synchronized void onLayer2Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs) {
        if (!isEnabled()) {
            return;
        }
        ModelPerformanceTelemetryOutboxRecord record = currentRecord();
        record.recordLayer2(elapsedMs);
        repository.save(record);
    }

    @Override
    public synchronized void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        if (!isEnabled()) {
            return;
        }
        ModelPerformanceTelemetryOutboxRecord record = currentRecord();
        record.recordDecision(action);
        repository.save(record);
    }

    @Override
    public synchronized void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
        if (!isEnabled()) {
            return;
        }
        ModelPerformanceTelemetryOutboxRecord record = currentRecord();
        record.recordEscalateProtectionTriggered();
        repository.save(record);
    }

    private ModelPerformanceTelemetryOutboxRecord currentRecord() {
        LocalDate period = LocalDate.now(clock);
        return repository.findByPeriod(period)
                .orElseGet(() -> repository.save(ModelPerformanceTelemetryOutboxRecord.initialize(period)));
    }
}
