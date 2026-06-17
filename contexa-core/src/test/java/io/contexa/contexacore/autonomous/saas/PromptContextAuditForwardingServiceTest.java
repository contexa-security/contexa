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
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.mapper.PromptContextAuditPayloadMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PromptContextAuditForwardingServiceTest {

    @Mock
    private PromptContextAuditForwardingOutboxRepository repository;

    @Mock
    private PromptContextAuditPayloadMapper payloadMapper;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private SaasPromptContextAuditDispatcher dispatcher;

    private PromptContextAuditForwardingService service;

    @BeforeEach
    void setUp() {
        Executor executor = Runnable::run;
        service = new PromptContextAuditForwardingService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Test
    void captureSavesAndDispatchesNewAudit() throws Exception {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-001").build();
        AuthorizedPromptContext authorizedPromptContext = new AuthorizedPromptContext(List.of(), 1, 0, 1, "THREAT_RUNTIME_CONTEXT", List.of("purpose_mismatch"));
        PromptContextAuditPayload payload = PromptContextAuditPayload.builder()
                .auditId("audit-001")
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .build();
        when(payloadMapper.map(event, "THREAT_RUNTIME_CONTEXT", authorizedPromptContext)).thenReturn(payload);
        when(repository.findByAuditId("audit-001")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"auditId\":\"audit-001\"}");
        when(repository.saveAndFlush(any(PromptContextAuditForwardingOutboxRecord.class))).thenAnswer(invocation -> {
            PromptContextAuditForwardingOutboxRecord saved = invocation.getArgument(0);
            saved.setId(11L);
            return saved;
        });

        service.capture(event, "THREAT_RUNTIME_CONTEXT", authorizedPromptContext);

        ArgumentCaptor<PromptContextAuditForwardingOutboxRecord> captor = ArgumentCaptor.forClass(PromptContextAuditForwardingOutboxRecord.class);
        verify(repository).saveAndFlush(captor.capture());
        PromptContextAuditForwardingOutboxRecord saved = captor.getValue();
        assertThat(saved.getAuditId()).isEqualTo("audit-001");
        assertThat(saved.getTenantExternalRef()).isEqualTo("tenant-acme");
        assertThat(saved.getStatus()).isEqualTo(PromptContextAuditForwardingOutboxRecord.STATUS_PENDING);
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        verify(payloadMapper, never()).resolveTenantExternalRef(event);
        verify(dispatcher).dispatch(11L);
    }

    @Test
    void captureDispatchesExistingAuditWithoutSaving() throws Exception {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-001").build();
        AuthorizedPromptContext authorizedPromptContext = new AuthorizedPromptContext(List.of(), 1, 0, 1, "THREAT_RUNTIME_CONTEXT", List.of());
        PromptContextAuditPayload payload = PromptContextAuditPayload.builder()
                .auditId("audit-001")
                .correlationId("corr-001")
                .build();
        when(payloadMapper.map(event, "THREAT_RUNTIME_CONTEXT", authorizedPromptContext)).thenReturn(payload);
        when(objectMapper.writeValueAsString(payload)).thenReturn("{}");
        when(repository.findByAuditId("audit-001")).thenReturn(Optional.of(PromptContextAuditForwardingOutboxRecord.builder()
                .id(7L)
                .auditId("audit-001")
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .build()));

        service.capture(event, "THREAT_RUNTIME_CONTEXT", authorizedPromptContext);

        verify(repository, never()).saveAndFlush(any(PromptContextAuditForwardingOutboxRecord.class));
        verify(dispatcher).dispatch(7L);
    }

    @Test
    void captureFallsBackToResolvedTenantExternalRefWhenPayloadOmitsIt() throws Exception {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-002").build();
        AuthorizedPromptContext authorizedPromptContext = new AuthorizedPromptContext(List.of(), 1, 1, 0, "THREAT_RUNTIME_CONTEXT", List.of());
        PromptContextAuditPayload payload = PromptContextAuditPayload.builder()
                .auditId("audit-002")
                .correlationId("corr-002")
                .tenantExternalRef(" ")
                .build();
        when(payloadMapper.map(event, "THREAT_RUNTIME_CONTEXT", authorizedPromptContext)).thenReturn(payload);
        when(payloadMapper.resolveTenantExternalRef(event)).thenReturn("tenant-fallback");
        when(repository.findByAuditId("audit-002")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"auditId\":\"audit-002\"}");
        when(repository.saveAndFlush(any(PromptContextAuditForwardingOutboxRecord.class))).thenAnswer(invocation -> {
            PromptContextAuditForwardingOutboxRecord saved = invocation.getArgument(0);
            saved.setId(17L);
            return saved;
        });

        service.capture(event, "THREAT_RUNTIME_CONTEXT", authorizedPromptContext);

        ArgumentCaptor<PromptContextAuditForwardingOutboxRecord> captor = ArgumentCaptor.forClass(PromptContextAuditForwardingOutboxRecord.class);
        verify(repository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getTenantExternalRef()).isEqualTo("tenant-fallback");
        assertThat(captor.getValue().getCreatedAt()).isNotNull();
        assertThat(captor.getValue().getUpdatedAt()).isNotNull();
        verify(payloadMapper).resolveTenantExternalRef(event);
        verify(dispatcher).dispatch(17L);
    }
}
