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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import io.contexa.contexacore.autonomous.saas.mapper.ThreatOutcomePayloadMapper;
import io.contexa.contexacore.domain.entity.ThreatOutcomeForwardingOutboxRecord;
import io.contexa.contexacore.repository.ThreatOutcomeForwardingOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SaasThreatOutcomeOutboxServiceTest {

    @Mock
    private ThreatOutcomeForwardingOutboxRepository repository;

    @Mock
    private ThreatOutcomePayloadMapper payloadMapper;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private SaasThreatOutcomeDispatcher dispatcher;

    private SaasThreatOutcomeOutboxService service;

    @BeforeEach
    void setUp() {
        Executor executor = Runnable::run;
        service = new SaasThreatOutcomeOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Test
    void captureSavesNewOutboxRecordWithTimestamps() throws Exception {
        AdminOverride adminOverride = AdminOverride.builder()
                .overrideId("ovr-001")
                .requestId("req-001")
                .approved(true)
                .originalRiskScore(0.9d)
                .originalConfidence(0.8d)
                .build();
        SecurityEvent originalEvent = SecurityEvent.builder()
                .eventId("evt-001")
                .metadata(Map.of("tenantId", "tenant-acme"))
                .build();
        ThreatOutcomePayload payload = ThreatOutcomePayload.builder()
                .outcomeId("outcome-001")
                .correlationId("corr-001")
                .build();
        when(payloadMapper.map(adminOverride, originalEvent)).thenReturn(payload);
        when(payloadMapper.resolveTenantExternalRef(originalEvent)).thenReturn("tenant-acme");
        when(repository.findByOutcomeId("outcome-001")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"outcomeId\":\"outcome-001\"}");
        when(repository.saveAndFlush(any(ThreatOutcomeForwardingOutboxRecord.class))).thenAnswer(invocation -> {
            ThreatOutcomeForwardingOutboxRecord saved = invocation.getArgument(0);
            saved.setId(41L);
            return saved;
        });

        service.capture(adminOverride, originalEvent);

        ArgumentCaptor<ThreatOutcomeForwardingOutboxRecord> captor = ArgumentCaptor.forClass(ThreatOutcomeForwardingOutboxRecord.class);
        verify(repository).saveAndFlush(captor.capture());
        ThreatOutcomeForwardingOutboxRecord saved = captor.getValue();
        assertThat(saved.getOutcomeId()).isEqualTo("outcome-001");
        assertThat(saved.getTenantExternalRef()).isEqualTo("tenant-acme");
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        verify(dispatcher).dispatch(41L);
    }
}
