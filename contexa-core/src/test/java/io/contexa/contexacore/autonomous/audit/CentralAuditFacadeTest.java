package io.contexa.contexacore.autonomous.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CentralAuditFacadeTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    private ObjectMapper objectMapper;
    private CentralAuditFacade facade;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        facade = new CentralAuditFacade(auditLogRepository, eventPublisher, objectMapper);
    }

    @Test
    @DisplayName("recordSync converts AuditRecord to AuditLog and saves")
    void recordSync_normalFlow_convertsAndSaves() {
        // given
        Map<String, Object> details = new HashMap<>();
        details.put("key1", "value1");

        AuditRecord record = AuditRecord.builder()
                .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                .principalName("admin1")
                .eventSource("CORE")
                .action("APPROVE")
                .decision("ALLOW")
                .reason("Legitimate user activity")
                .outcome("APPROVED")
                .details(details)
                .build();

        // when
        facade.recordSync(record);

        // then
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertThat(saved.getPrincipalName()).isEqualTo("admin1");
        assertThat(saved.getAction()).isEqualTo("APPROVE");
        assertThat(saved.getDecision()).isEqualTo("ALLOW");
        assertThat(saved.getReason()).isEqualTo("Legitimate user activity");
        assertThat(saved.getDetails()).contains("key1");
    }

    @Test
    @DisplayName("recordSync with null details saves without details JSON")
    void recordSync_nullDetails_savesWithoutDetailsJson() {
        // given
        AuditRecord record = AuditRecord.builder()
                .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                .principalName("admin1")
                .action("APPROVE")
                .build();

        // when
        facade.recordSync(record);

        // then
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        assertThat(captor.getValue().getDetails()).isNull();
    }

    @Test
    @DisplayName("recordAsync publishes ApplicationEvent")
    void recordAsync_normalFlow_publishesEvent() {
        // given
        AuditRecord record = AuditRecord.builder()
                .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                .principalName("admin1")
                .action("APPROVE")
                .build();

        // when
        facade.recordAsync(record);

        // then
        ArgumentCaptor<AuditRecordEvent> captor = ArgumentCaptor.forClass(AuditRecordEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        assertThat(captor.getValue().getAuditRecord()).isEqualTo(record);
    }

    @Test
    @DisplayName("recordAsync falls back to sync on publish failure")
    void recordAsync_publishFails_fallsBackToSync() {
        // given
        AuditRecord record = AuditRecord.builder()
                .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                .principalName("admin1")
                .action("APPROVE")
                .decision("ALLOW")
                .build();

        doThrow(new RuntimeException("Event publish failed"))
                .when(eventPublisher).publishEvent(any(AuditRecordEvent.class));

        // when
        facade.recordAsync(record);

        // then - sync fallback should save via repository
        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    @DisplayName("recordSync handles save exception gracefully")
    void recordSync_saveException_handlesGracefully() {
        // given
        AuditRecord record = AuditRecord.builder()
                .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                .principalName("admin1")
                .action("APPROVE")
                .build();

        doThrow(new RuntimeException("DB error"))
                .when(auditLogRepository).save(any(AuditLog.class));

        // when - should not throw
        facade.recordSync(record);

        // then - exception handled internally
        verify(auditLogRepository).save(any(AuditLog.class));
    }
}
