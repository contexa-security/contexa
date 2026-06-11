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
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.mapper.SecurityDecisionForwardingPayloadMapper;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SaasDecisionOutboxServiceTest {

    @Mock
    private SecurityDecisionForwardingOutboxRepository repository;

    @Mock
    private SecurityDecisionForwardingPayloadMapper payloadMapper;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private SaasDecisionDispatcher dispatcher;

    private SaasDecisionOutboxService service;

    @BeforeEach
    void setUp() {
        Executor executor = Runnable::run;
        service = new SaasDecisionOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Test
    void captureSavesNewOutboxRecordWithTimestamps() throws Exception {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-001")
                .metadata(Map.of("tenantId", "tenant-acme"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        SecurityDecisionForwardingPayload payload = SecurityDecisionForwardingPayload.builder()
                .correlationId("corr-001")
                .decision("CHALLENGE")
                .build();
        when(payloadMapper.map(context)).thenReturn(payload);
        when(repository.findByCorrelationId("corr-001")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"correlationId\":\"corr-001\"}");
        when(repository.saveAndFlush(any(SecurityDecisionForwardingOutboxRecord.class))).thenAnswer(invocation -> {
            SecurityDecisionForwardingOutboxRecord saved = invocation.getArgument(0);
            saved.setId(31L);
            return saved;
        });

        service.capture(context);

        ArgumentCaptor<SecurityDecisionForwardingOutboxRecord> captor = ArgumentCaptor.forClass(SecurityDecisionForwardingOutboxRecord.class);
        verify(repository).saveAndFlush(captor.capture());
        SecurityDecisionForwardingOutboxRecord saved = captor.getValue();
        assertThat(saved.getCorrelationId()).isEqualTo("corr-001");
        assertThat(saved.getTenantExternalRef()).isEqualTo("tenant-acme");
        assertThat(saved.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING);
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        verify(dispatcher).dispatch(31L);
    }

    @Test
    void captureDispatchesExistingRecordWhenCorrelationInsertRaces() throws Exception {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-002")
                .metadata(Map.of("tenantId", "tenant-acme"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        SecurityDecisionForwardingPayload payload = SecurityDecisionForwardingPayload.builder()
                .correlationId("corr-002")
                .decision("BLOCK")
                .build();
        when(payloadMapper.map(context)).thenReturn(payload);
        when(repository.findByCorrelationId("corr-002")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"correlationId\":\"corr-002\"}");
        when(repository.saveAndFlush(any(SecurityDecisionForwardingOutboxRecord.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate correlation"));
        when(repository.findTopByCorrelationIdOrderByIdDesc("corr-002")).thenReturn(Optional.of(SecurityDecisionForwardingOutboxRecord.builder()
                .id(41L)
                .correlationId("corr-002")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .status(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING)
                .build()));

        service.capture(context);

        verify(dispatcher).dispatch(41L);
    }
}
