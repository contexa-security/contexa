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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityMonitorDtos.IpGroupView;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SecurityMonitorController")
class SecurityMonitorControllerTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private CsvExportService csvExportService;

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

            String view = controller.monitor(null, null, null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
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

            String view = controller.monitor("AUTHENTICATION_SUCCESS", null, null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
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

            String view = controller.monitor(null, "AFTER_HOURS", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
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

            String view = controller.monitor(null, "HIGH_RISK", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
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

            String view = controller.monitor(null, "DECISION_ALLOW", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
        }

        @Test
        @DisplayName("should handle DECISION_DENY filter")
        void decisionDenyFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndDecision(
                    any(LocalDateTime.class), eq("DENY"), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "DECISION_DENY", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
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
                    .thenReturn(List.<Object[]>of(new Object[]{"10.0.0.1", 7L, "2026-04-21 10:00:00"}));
            when(auditLogRepository.countDistinctIpGroupsSince(any(LocalDateTime.class)))
                    .thenReturn(1L);

            String view = controller.monitor(null, "DISTINCT_IP", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
            @SuppressWarnings("unchecked")
            List<IpGroupView> ipGroups = (List<IpGroupView>) model.getAttribute("ipGroups");
            assertThat(ipGroups).hasSize(1);
            assertThat(ipGroups.get(0)).isInstanceOf(IpGroupView.class);
            assertThat(ipGroups.get(0).ip()).isEqualTo("10.0.0.1");
            assertThat(ipGroups.get(0).count()).isEqualTo(7L);
            assertThat(ipGroups.get(0).lastAccess()).isEqualTo("2026-04-21 10:00:00");
            assertThat(model.getAttribute("totalIpGroups")).isEqualTo(1L);
        }

        @Test
        @DisplayName("should handle ZT_ALLOW filter")
        void ztAllowFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByCategoryAndDecision(
                    eq("SECURITY_DECISION"), eq("ALLOW"), any(LocalDateTime.class), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "ZT_ALLOW", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
        }

        @Test
        @DisplayName("should handle default filter as category-based search")
        void defaultFilter() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            when(auditLogRepository.findByTimestampAfterAndCategory(
                    any(LocalDateTime.class), eq("CUSTOM_FILTER"), any(Pageable.class)))
                    .thenReturn(Page.empty());

            String view = controller.monitor(null, "CUSTOM_FILTER", null, 24, 0, model);

            assertThat(view).isEqualTo("contexa/admin/security-monitor");
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
    @DisplayName("the integrity of a decision record")
    class DecisionRecordIntegrity {

        private final HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                .encodeToString("k1-0123456789abcdef0123456789abcd".getBytes())), null);

        private AuditLog sealedRecord() {
            AuditLog record = AuditLog.builder().id(7L).eventCategory("SECURITY_DECISION").principalName("alice")
                    .decision("BLOCK").timestamp(LocalDateTime.now()).build();
            DecisionRecordSeal.seal(record, null, signer);
            return record;
        }

        private Object integrityOf(AuditLog record) {
            controller.setEvidenceSigner(signer);
            when(auditLogRepository.findById(7L)).thenReturn(Optional.of(record));
            Model model = new ConcurrentModel();
            controller.detail(7L, model, new RedirectAttributesModelMap());
            return model.getAttribute("integrity");
        }

        @Test
        @DisplayName("a record without its signature, once older sealed records are kept, is shown as changed")
        void anUnsignedRecordInsideTheChain() {
            AuditLog record = sealedRecord();
            record.setRecordSignature(null);
            when(auditLogRepository.existsByEventCategoryAndRecordHashIsNotNullAndIdLessThan("SECURITY_DECISION", 7L))
                    .thenReturn(true);

            assertThat(integrityOf(record)).isEqualTo("MISMATCH");
        }

        @Test
        @DisplayName("a record from before sealing began stays not verifiable")
        void aRecordFromBeforeSealing() {
            AuditLog record = AuditLog.builder().id(7L).eventCategory("SECURITY_DECISION").principalName("alice").build();

            assertThat(integrityOf(record)).isEqualTo("UNVERIFIABLE");
        }

        @Test
        @DisplayName("a record naming a key never held, in the time of the active key, is shown as changed")
        void aKeyNeverHeld() {
            AuditLog record = sealedRecord();
            record.setSignatureKeyId("forged-key");
            when(auditLogRepository.existsByEventCategoryAndSignatureKeyIdAndIdLessThan("SECURITY_DECISION", "k1", 7L))
                    .thenReturn(true);

            assertThat(integrityOf(record)).isEqualTo("MISMATCH");
        }

        @Test
        @DisplayName("a record naming a key from before the active key came into use stays not verifiable")
        void aKeyFromBeforeTheActiveOne() {
            AuditLog record = sealedRecord();
            record.setSignatureKeyId("ephemeral-1a2b3c4d");

            assertThat(integrityOf(record)).isEqualTo("UNVERIFIABLE");
        }
    }

    @Nested
    @DisplayName("docs/agent A5-5 (AM-5)")
    class AgentDecisionRecords {

        @Test
        @DisplayName("a subject chip lists the decisions of that subject kind; an unknown one lists as before")
        void subjectChip() {
            Page<AuditLog> agents = new PageImpl<>(List.of(AuditLog.builder().id(7L).principalName("alice")
                    .decision("BLOCK").subjectKind("DELEGATED_AGENT").agentId("report-agent").build()));
            when(auditLogRepository.findByTimestampAfterAndSubjectKind(any(LocalDateTime.class),
                    eq("DELEGATED_AGENT"), any(Pageable.class))).thenReturn(agents);
            when(auditLogRepository.findByTimestampAfter(any(LocalDateTime.class), any(Pageable.class)))
                    .thenReturn(Page.empty());
            Model model = new ConcurrentModel();

            controller.monitor(null, null, null, "DELEGATED_AGENT", 24, 0, model);

            assertThat(model.getAttribute("logPage")).isEqualTo(agents);
            assertThat(model.getAttribute("subject")).isEqualTo("DELEGATED_AGENT");

            Model other = new ConcurrentModel();
            controller.monitor(null, null, null, "ANYONE", 24, 0, other);
            assertThat(other.getAttribute("subject")).isNull();
            verify(auditLogRepository).findByTimestampAfter(any(LocalDateTime.class), any(Pageable.class));
        }

        @Test
        @DisplayName("an agent's decision shows the delegation it ran under, as the delegation record states it")
        void delegationOfTheDecision() {
            InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry();
            AgentDelegation delegation = delegations.record(new AgentDelegationRequest(null, "alice", "report-agent",
                    null, "DATA_EXPORT", "Export this week's HX-310 packages", List.of("EXPORT"), List.of("HX-310"),
                    false, null, null, Instant.now().minusSeconds(3600), Instant.now().plusSeconds(3600), "alice", null));
            SecurityMonitorController withDelegations = new SecurityMonitorController(auditLogRepository,
                    csvExportService, delegations);
            AuditLog record = AuditLog.builder().id(8L).principalName("alice").decision("BLOCK")
                    .agentId("report-agent").delegationId(delegation.delegationId()).build();
            when(auditLogRepository.findById(8L)).thenReturn(Optional.of(record));
            Model model = new ConcurrentModel();

            withDelegations.detail(8L, model, new RedirectAttributesModelMap());

            assertThat(model.getAttribute("delegation")).isEqualTo(delegation);
            Model unknown = new ConcurrentModel();
            controller.detail(8L, unknown, new RedirectAttributesModelMap());
            assertThat(unknown.getAttribute("delegation")).as("no delegation registry").isNull();
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
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.detail(1L, model, ra);

            assertThat(view).isEqualTo("contexa/admin/security-monitor-detail");
            assertThat(model.getAttribute("log")).isEqualTo(auditLog);
            assertThat(model.getAttribute("activePage")).isEqualTo("security-monitor");
        }

        @Test
        @DisplayName("should redirect with error when audit log not found")
        void notFound() {
            Model model = new ConcurrentModel();
            RedirectAttributes ra = new RedirectAttributesModelMap();
            when(auditLogRepository.findById(999L)).thenReturn(Optional.empty());

            String view = controller.detail(999L, model, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/security-monitor");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("999");
        }
    }

    @Nested
    @DisplayName("export")
    class Export {

        @Test
        @DisplayName("should export audit logs to CSV successfully")
        void exportCsv() throws Exception {
            HttpServletResponse httpResponse = mock(HttpServletResponse.class);
            when(auditLogRepository.findByTimestampAfter(any(LocalDateTime.class), any(Pageable.class)))
                    .thenReturn(new PageImpl<>(List.of(new AuditLog())));

            controller.exportCsv(null, null, 24, httpResponse);

            verify(csvExportService).export(eq(httpResponse), eq("audit-log"), anyList(), any());
        }
    }
}
