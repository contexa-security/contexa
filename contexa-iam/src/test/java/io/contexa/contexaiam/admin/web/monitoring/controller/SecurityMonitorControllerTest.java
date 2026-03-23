package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SecurityMonitorController")
class SecurityMonitorControllerTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private SecurityMonitorController controller;

    @Nested
    @DisplayName("monitor")
    class Monitor {

        @Test
        @DisplayName("should return security monitor view with default params")
        void defaultParams() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfter(any(LocalDateTime.class), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, null, 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
            assertThat(model.getAttribute("activePage")).isEqualTo("security-monitor");
            assertThat(model.getAttribute("logPage")).isNotNull();
            assertThat(model.getAttribute("hours")).isEqualTo(24);
            assertThat(model.getAttribute("totalCount")).isEqualTo(100L);
            assertThat(model.getAttribute("authSuccess")).isEqualTo(50L);
            assertThat(model.getAttribute("authFailure")).isEqualTo(10L);
            assertThat(model.getAttribute("securityDecision")).isEqualTo(30L);
            assertThat(model.getAttribute("userBlocked")).isEqualTo(5L);
            assertThat(model.getAttribute("mfaVerified")).isEqualTo(20L);
            assertThat(model.getAttribute("adminOverride")).isEqualTo(3L);
        }

        @Test
        @DisplayName("should filter by category when category is provided")
        void withCategory() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndCategory(
                    any(LocalDateTime.class), eq("AUTHENTICATION_SUCCESS"), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor("AUTHENTICATION_SUCCESS", null, 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
            assertThat(model.getAttribute("category")).isEqualTo("AUTHENTICATION_SUCCESS");
            verify(auditLogRepository).findByTimestampAfterAndCategory(
                    any(LocalDateTime.class), eq("AUTHENTICATION_SUCCESS"), any(Pageable.class));
        }

        @Test
        @DisplayName("should handle AFTER_HOURS filter")
        void afterHoursFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findAfterHoursAccess(any(LocalDateTime.class), any()))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "AFTER_HOURS", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
            assertThat(model.getAttribute("filterType")).isEqualTo("AFTER_HOURS");
        }

        @Test
        @DisplayName("should handle HIGH_RISK filter")
        void highRiskFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndRiskScoreGte(
                    any(LocalDateTime.class), eq(0.4), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "HIGH_RISK", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
            assertThat(model.getAttribute("filterType")).isEqualTo("HIGH_RISK");
        }

        @Test
        @DisplayName("should handle DECISION_ALLOW filter")
        void decisionAllowFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndDecision(
                    any(LocalDateTime.class), eq("ALLOW"), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "DECISION_ALLOW", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
        }

        @Test
        @DisplayName("should handle DECISION_DENY filter")
        void decisionDenyFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndDecision(
                    any(LocalDateTime.class), eq("DENY"), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "DECISION_DENY", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
        }

        @Test
        @DisplayName("should handle DISTINCT_IP filter with IP groups")
        void distinctIpFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndClientIpNotNull(
                    any(LocalDateTime.class), any(Pageable.class)))
                    .thenReturn(Page.empty());
            when(auditLogRepository.findIpGroupsSince(any(LocalDateTime.class), anyInt(), anyInt()))
                    .thenReturn(java.util.List.of());
            when(auditLogRepository.countDistinctIpGroupsSince(any(LocalDateTime.class)))
                    .thenReturn(0L);

            String view = controller.monitor(null, "DISTINCT_IP", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
            assertThat(model.getAttribute("ipGroups")).isNotNull();
            assertThat(model.getAttribute("totalIpGroups")).isEqualTo(0L);
        }

        @Test
        @DisplayName("should handle ZT_ALLOW filter")
        void ztAllowFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByCategoryAndDecision(
                    eq("SECURITY_DECISION"), eq("ALLOW"), any(LocalDateTime.class), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "ZT_ALLOW", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
        }

        @Test
        @DisplayName("should handle default filter as category-based search")
        void defaultFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndCategory(
                    any(LocalDateTime.class), eq("CUSTOM_FILTER"), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "CUSTOM_FILTER", 24, 0, model);

            assertThat(view).isEqualTo("admin/security-monitor");
        }

        private void stubRepositoryCounts() {
            when(auditLogRepository.countByTimestampAfter(any(LocalDateTime.class))).thenReturn(100L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("AUTHENTICATION_SUCCESS"), any(LocalDateTime.class))).thenReturn(50L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("AUTHENTICATION_FAILURE"), any(LocalDateTime.class))).thenReturn(10L);
            when(auditLogRepository.countZeroTrustTotalSince(any(LocalDateTime.class))).thenReturn(30L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("USER_BLOCKED"), any(LocalDateTime.class))).thenReturn(5L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("MFA_VERIFICATION_SUCCESS"), any(LocalDateTime.class))).thenReturn(20L);
            when(auditLogRepository.countAdminOverridesSince(any(LocalDateTime.class))).thenReturn(3L);
        }
    }

    @Nested
    @DisplayName("detail")
    class Detail {

        @Test
        @DisplayName("should return detail view with audit log")
        void success() {
            Model model = new ConcurrentModel();
            AuditLog auditLog = AuditLog.builder()
                    .id(1L)
                    .principalName("user1")
                    .action("LOGIN")
                    .decision("ALLOW")
                    .eventCategory("AUTHENTICATION_SUCCESS")
                    .build();
            when(auditLogRepository.findById(1L)).thenReturn(Optional.of(auditLog));

            String view = controller.detail(1L, model);

            assertThat(view).isEqualTo("admin/security-monitor-detail");
            assertThat(model.getAttribute("log")).isEqualTo(auditLog);
            assertThat(model.getAttribute("activePage")).isEqualTo("security-monitor");
        }

        @Test
        @DisplayName("should throw exception when audit log not found")
        void notFound() {
            Model model = new ConcurrentModel();
            when(auditLogRepository.findById(999L)).thenReturn(Optional.empty());

            assertThrows(IllegalArgumentException.class,
                    () -> controller.detail(999L, model));
        }
    }
}
