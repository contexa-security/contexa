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
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityEventQueries;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityEventQueries.Criteria;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.PageRequest;
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
import org.springframework.context.support.StaticMessageSource;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Locale;
import java.util.List;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
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

    @Mock
    private SecurityEventQueries eventQueries;

    @BeforeEach
    void theListReads() {
        lenient().when(eventQueries.ids(any(), any())).thenAnswer(invocation -> new PageImpl<>(List.of(),
                invocation.getArgument(1, Pageable.class), 0));
        controller.setEventQueries(eventQueries);
    }

    @Nested
    @DisplayName("monitor")
    class Monitor {

        @Test
        @DisplayName("should return security monitor view with default params")
        void defaultParams() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();

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
        @DisplayName("K103: a link's start is where the list starts, and the screen's links keep it")
        void aLinksStartIsWhereTheListStarts() {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            LocalDateTime hour = LocalDateTime.now().minusDays(7).withMinute(0).withSecond(0).withNano(0);
            String start = hour.atZone(ZoneId.systemDefault()).toInstant().toString();

            controller.monitor("SECURITY_DECISION", null, null, null, 168, start, 0, model);

            Criteria criteria = criteria();
            assertThat(criteria.since()).isEqualTo(hour);
            assertThat(criteria.category()).isEqualTo("SECURITY_DECISION");
            verify(auditLogRepository).countAdminOverridesBetween(eq(hour), any(LocalDateTime.class));
            assertThat(model.getAttribute("from")).isEqualTo(start);
        }

        @Test
        @DisplayName("K103: a start after now or one that is no instant leaves the last hours")
        void aStartAfterNowOrUnreadableLeavesTheLastHours() {
            LocalDateTime now = LocalDateTime.of(2026, 11, 18, 10, 30);
            LocalDateTime hour = now.minusDays(7).withMinute(0);

            assertThat(SecurityMonitorController.start(hour.atZone(ZoneId.systemDefault()).toInstant().toString(), now))
                    .isEqualTo(hour);
            assertThat(SecurityMonitorController.start(now.plusHours(1).atZone(ZoneId.systemDefault()).toInstant()
                    .toString(), now)).isNull();
            assertThat(SecurityMonitorController.start("yesterday", now)).isNull();
            assertThat(SecurityMonitorController.start(" ", now)).isNull();
        }

        @Test
        @DisplayName("K105: the admin override card's filter lists the overrides the card counts, the CSV too")
        void theOverrideCardsFilterListsTheOverridesItCounts() throws Exception {
            Model model = new ConcurrentModel();
            stubRepositoryCounts();
            doAnswer(invocation -> ((Supplier<?>) invocation.getArgument(3)).get()).when(csvExportService)
                    .export(any(), any(), anyList(), any());

            controller.monitor("ADMIN_OVERRIDE", "ADMIN_OVERRIDE_APPLIED", null, 24, 0, model);
            controller.exportCsv("ADMIN_OVERRIDE", "ADMIN_OVERRIDE_APPLIED", 24, mock(HttpServletResponse.class));

            ArgumentCaptor<Criteria> read = ArgumentCaptor.forClass(Criteria.class);
            verify(eventQueries, times(2)).ids(read.capture(), any(Pageable.class));
            assertThat(read.getAllValues()).allMatch(c -> "ADMIN_OVERRIDE_APPLIED".equals(c.filter()) && c.until() != null);
        }

        @Test
        @DisplayName("K138: a category, a filter or the addresses, each narrowed by the user name and the subject kind")
        void everyListIsNarrowedByTheNameAndTheSubject() {
            stubRepositoryCounts();
            when(eventQueries.addresses(any(), any())).thenReturn(new PageImpl<>(List.<Object[]>of(
                    new Object[]{"10.0.0.1", 7L, "2026-04-21 10:00:00"}), PageRequest.of(0, 20), 1));
            for (String filter : new String[]{"AFTER_HOURS", "HIGH_RISK", "DECISION_ALLOW", "DECISION_DENY", "ZT_ALLOW",
                    "ZT_BLOCK", "ZT_CHALLENGE", "ZT_ESCALATE", "SEAL_MISMATCH", "CUSTOM_FILTER", "DISTINCT_IP"}) {
                Model model = new ConcurrentModel();
                clearInvocations(eventQueries);

                controller.monitor("AUTHENTICATION_SUCCESS", filter, " Bob ", "DELEGATED_AGENT", 24, null, 0, model);

                Criteria criteria = criteria();
                assertThat(criteria.filter()).isEqualTo(filter);
                assertThat(criteria.keyword()).isEqualTo(" Bob ");
                assertThat(criteria.subjectKind()).isEqualTo("DELEGATED_AGENT");
                assertThat(model.getAttribute("filterType")).isEqualTo(filter);
                assertThat(model.getAttribute("subject")).isEqualTo("DELEGATED_AGENT");
            }
            clearInvocations(eventQueries);
            Model addresses = new ConcurrentModel();
            controller.monitor(null, "DISTINCT_IP", "bob", null, 24, null, 0, addresses);
            @SuppressWarnings("unchecked")
            List<IpGroupView> groups = (List<IpGroupView>) addresses.getAttribute("ipGroups");
            assertThat(groups).extracting(IpGroupView::ip, IpGroupView::count).containsExactly(tuple("10.0.0.1", 7L));
            assertThat(groups.get(0).lastAccess()).isEqualTo("2026-04-21 10:00:00");
            assertThat(addresses.getAttribute("totalIpGroups")).isEqualTo(1L);
            ArgumentCaptor<Criteria> read = ArgumentCaptor.forClass(Criteria.class);
            verify(eventQueries).addresses(read.capture(), any());
            assertThat(read.getValue().keyword()).isEqualTo("bob");
        }

        @Test
        @DisplayName("K139: a page before the first reads the first, a page after the last reads the last")
        void aPageOutOfTheListReadsItsEnd() {
            stubRepositoryCounts();
            doAnswer(invocation -> new PageImpl<>(List.of(), invocation.getArgument(1, Pageable.class), 45))
                    .when(eventQueries).ids(any(), any());
            Model before = new ConcurrentModel();
            Model after = new ConcurrentModel();

            controller.monitor(null, null, null, null, 24, null, -3, before);
            controller.monitor(null, null, null, null, 24, null, 9, after);

            assertThat(((Page<?>) before.getAttribute("logPage")).getNumber()).isZero();
            assertThat(((Page<?>) after.getAttribute("logPage")).getNumber()).isEqualTo(2);
        }

        /** The criteria of the list's last read. */
        private Criteria criteria() {
            ArgumentCaptor<Criteria> read = ArgumentCaptor.forClass(Criteria.class);
            verify(eventQueries, atLeastOnce()).ids(read.capture(), any(Pageable.class));
            return read.getValue();
        }

        private void stubRepositoryCounts() {
            when(auditLogRepository.countByTimestampAfter(any(LocalDateTime.class))).thenReturn(100L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("AUTHENTICATION_SUCCESS"), any(LocalDateTime.class))).thenReturn(50L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("AUTHENTICATION_FAILURE"), any(LocalDateTime.class))).thenReturn(10L);
            when(auditLogRepository.countZeroTrustTotalSince(any(LocalDateTime.class))).thenReturn(30L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("USER_BLOCKED"), any(LocalDateTime.class))).thenReturn(5L);
            when(auditLogRepository.countByEventCategoryAndTimestampAfter(eq("MFA_VERIFICATION_SUCCESS"), any(LocalDateTime.class))).thenReturn(20L);
            when(auditLogRepository.countAdminOverridesBetween(any(LocalDateTime.class), any(LocalDateTime.class)))
                    .thenReturn(3L);
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
            Model model = new ConcurrentModel();

            controller.monitor(null, null, null, "DELEGATED_AGENT", 24, 0, model);
            Model other = new ConcurrentModel();
            controller.monitor(null, null, null, "ANYONE", 24, 0, other);

            ArgumentCaptor<Criteria> read = ArgumentCaptor.forClass(Criteria.class);
            verify(eventQueries, times(2)).ids(read.capture(), any(Pageable.class));
            assertThat(read.getAllValues()).extracting(Criteria::subjectKind).containsExactly("DELEGATED_AGENT", null);
            assertThat(model.getAttribute("subject")).isEqualTo("DELEGATED_AGENT");
            assertThat(other.getAttribute("subject")).isNull();
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

        /** IAM-D05/D06: the notice is in the administrator's language and names the ID without separators. */
        @Test
        @DisplayName("says in the administrator's language that the ID names no event, the ID as typed")
        void notFoundIsSaidInTheAdministratorsLanguage() {
            StaticMessageSource messages = new StaticMessageSource();
            messages.addMessage("admin.security.monitor.not.found", Locale.getDefault(), "no event {0}");
            controller.setMessageSource(messages);
            RedirectAttributes ra = new RedirectAttributesModelMap();
            when(auditLogRepository.findById(999999L)).thenReturn(Optional.empty());

            controller.detail(999999L, new ConcurrentModel(), ra);

            assertThat(ra.getFlashAttributes().get("errorMessage")).isEqualTo("no event 999999");
        }
    }

    @Nested
    @DisplayName("export")
    class Export {

        @Test
        @DisplayName("should export audit logs to CSV successfully")
        void exportCsv() throws Exception {
            HttpServletResponse httpResponse = mock(HttpServletResponse.class);

            controller.exportCsv(null, null, 24, httpResponse);

            verify(csvExportService).export(eq(httpResponse), eq("audit-log"), anyList(), any());
        }

        @Test
        @DisplayName("K108: the CSV reads the rows the screen lists: its subject, its user name, its address filter")
        void theCsvReadsWhatTheScreenLists() throws Exception {
            doAnswer(invocation -> ((Supplier<?>) invocation.getArgument(3)).get()).when(csvExportService)
                    .export(any(), any(), anyList(), any());

            controller.exportCsv(null, null, 24, null, "bob", "DELEGATED_AGENT", mock(HttpServletResponse.class));
            controller.exportCsv("AUTHENTICATION_FAILURE", null, 24, null, " Bob ", null, mock(HttpServletResponse.class));
            controller.exportCsv(null, "DISTINCT_IP", 24, null, null, null, mock(HttpServletResponse.class));

            ArgumentCaptor<Criteria> read = ArgumentCaptor.forClass(Criteria.class);
            verify(eventQueries, times(3)).ids(read.capture(), any(Pageable.class));
            assertThat(read.getAllValues()).extracting(Criteria::category, Criteria::filter, Criteria::keyword,
                    Criteria::subjectKind).containsExactly(tuple(null, null, "bob", "DELEGATED_AGENT"),
                    tuple("AUTHENTICATION_FAILURE", null, " Bob ", null), tuple(null, "DISTINCT_IP", null, null));
        }

        @Test
        @DisplayName("K92: the list reads the records of the page's IDs, in their order")
        void theListReadsTheRecordsOfItsIds() {
            doReturn(new PageImpl<>(List.of(9L, 4L), PageRequest.of(1, 20), 41)).when(eventQueries).ids(any(), any());
            when(auditLogRepository.findAllById(List.of(9L, 4L))).thenReturn(List.of(AuditLog.builder().id(4L).build(),
                    AuditLog.builder().id(9L).build()));
            Model model = new ConcurrentModel();

            controller.monitor("SECURITY_DECISION", "SEAL_MISMATCH", null, null, 168, null, 1, model);

            Page<?> page = (Page<?>) model.getAttribute("logPage");
            assertThat(page.getTotalElements()).isEqualTo(41);
            assertThat(page.getContent()).map(AuditLog.class::cast).extracting(AuditLog::getId).containsExactly(9L, 4L);
            assertThat(model.getAttribute("periods")).isEqualTo(SecurityMonitorController.PERIODS);
            assertThat(SecurityMonitorController.PERIODS).extracting(SecurityMonitorController.PeriodChoice::hours)
                    .containsExactly(1, 6, 24, 72, 168, 720, 2160);
        }
    }
}
