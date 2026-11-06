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
package io.contexa.contexacore.autonomous.signal;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.QueryTimeoutException;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * docs/agent A5-8: a revocation or risk signal invalidates the decision in force for the subject it names and its
 * cache, so the next request is decided again; a restriction stays; an event that ends sessions signs the subject out;
 * a token pushed again is not acted on twice.
 */
class RiskSignalReceiverTest {

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final ZeroTrustSecurityService zeroTrust = mock(ZeroTrustSecurityService.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final RiskSignalReceiver receiver = new RiskSignalReceiver(actions, zeroTrust,
            subjectId -> RiskSignalReceiver.userOf(subjectId,
                    email -> "carol@example.test".equals(email) ? "carol" : null), audit);

    @Test
    void aTokenAStoreDidNotLetBeActedOnAsksForTheLogoutAndIsActedOnWhenSentAgain() {
        ZeroTrustActionRepository failing = mock(ZeroTrustActionRepository.class);
        doThrow(new QueryTimeoutException("no answer")).doNothing().when(failing).removeLogoutData("alice");
        RiskSignalReceiver acting = new RiskSignalReceiver(failing, zeroTrust,
                subjectId -> RiskSignalReceiver.userOf(subjectId, email -> null), audit);
        SecurityEventToken revoked = token("jti-outage", Map.of(
                SecurityEventToken.SESSION_REVOKED, Map.of("subject", issSub("alice"))));

        assertThatThrownBy(() -> acting.receive(revoked)).isInstanceOf(QueryTimeoutException.class);
        verify(zeroTrust).invalidateAllUserSessions(eq("alice"), anyString());

        assertThat(acting.receive(revoked).subjects()).containsExactly("alice");
    }

    @Test
    void aFailureThatIsNoOutageKeepsTheTokenAsSeen() {
        ZeroTrustActionRepository failing = mock(ZeroTrustActionRepository.class);
        doThrow(new IllegalStateException("a bug")).when(failing).removeLogoutData("alice");
        RiskSignalReceiver acting = new RiskSignalReceiver(failing, zeroTrust,
                subjectId -> RiskSignalReceiver.userOf(subjectId, email -> null), audit);
        SecurityEventToken revoked = token("jti-bug", Map.of(
                SecurityEventToken.SESSION_REVOKED, Map.of("subject", issSub("alice"))));

        assertThatThrownBy(() -> acting.receive(revoked)).isInstanceOf(IllegalStateException.class);

        assertThat(acting.receive(revoked).subjects()).isEmpty();
    }

    @Test
    void aRiskSignalHasTheSubjectDecidedAgainAndARestrictionStays() {
        actions.saveAction("alice", ZeroTrustAction.ALLOW, Map.of());
        actions.saveAction("bob", ZeroTrustAction.BLOCK, Map.of());

        RiskSignalReceiver.Receipt receipt = receiver.receive(token("jti-1", Map.of(
                SecurityEventToken.RISK_LEVEL_CHANGE, Map.of("subject", issSub("alice"), "current_level", "HIGH"),
                SecurityEventToken.TOKEN_CLAIMS_CHANGE, Map.of("subject", issSub("bob")))));

        assertThat(receipt.subjects()).containsExactlyInAnyOrder("alice", "bob");
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(actions.getCurrentAction("bob")).isEqualTo(ZeroTrustAction.BLOCK);
        verify(zeroTrust).invalidateDecisionCache("alice");
        verify(zeroTrust, never()).invalidateAllUserSessions(anyString(), anyString());
        assertThat(categories()).containsOnly(AuditEventCategory.RISK_SIGNAL_RECEIVED);
    }

    @Test
    void aRevokedSessionSignsTheSubjectOutAndAPushedAgainTokenIsNotActedOnTwice() {
        SecurityEventToken revoked = new SecurityEventToken("https://idp.test", "jti-2", Instant.now(),
                Map.of("format", "email", "email", "carol@example.test"),
                Map.of(SecurityEventToken.SESSION_REVOKED, Map.of()));

        assertThat(receiver.receive(revoked).subjects()).containsExactly("carol");
        assertThat(receiver.receive(revoked).subjects()).isEmpty();

        verify(zeroTrust).invalidateAllUserSessions(eq("carol"), anyString());
    }

    private RiskSignalReceiver receiverWith(IForceLogoutService forceLogout) {
        return new RiskSignalReceiver(actions, zeroTrust, subjectId -> RiskSignalReceiver.userOf(subjectId, null), audit,
                forceLogout);
    }

    @Test
    void anEventThatEndsSessionsEndsWhatTheForcedLogoutReaches() {
        IForceLogoutService forceLogout = mock(IForceLogoutService.class);

        receiverWith(forceLogout).receive(token("jti-6", Map.of(
                SecurityEventToken.CREDENTIAL_COMPROMISE, Map.of("subject", issSub("alice")))));

        verify(forceLogout).forceLogoutByUserId(eq("alice"), anyString());
    }

    @Test
    void anEventThatOnlyDecidesAgainEndsNothing() {
        IForceLogoutService forceLogout = mock(IForceLogoutService.class);

        receiverWith(forceLogout).receive(token("jti-7", Map.of(
                SecurityEventToken.RISK_LEVEL_CHANGE, Map.of("subject", issSub("alice")))));

        verify(forceLogout, never()).forceLogoutByUserId(anyString(), anyString());
    }

    @Test
    void aForcedLogoutThatFailsCostsNeitherTheAnswerNorTheAudit() {
        IForceLogoutService forceLogout = mock(IForceLogoutService.class);
        doThrow(new IllegalStateException("store down")).when(forceLogout).forceLogoutByUserId(anyString(), anyString());

        RiskSignalReceiver.Receipt receipt = receiverWith(forceLogout).receive(token("jti-8", Map.of(
                SecurityEventToken.ACCOUNT_DISABLED, Map.of("subject", issSub("alice")))));

        assertThat(receipt.subjects()).containsExactly("alice");
        assertThat(categories()).containsOnly(AuditEventCategory.RISK_SIGNAL_RECEIVED);
    }

    @Test
    void aSubjectThatNamesNoUserIsRecordedAndNothingIsInvalidated() {
        actions.saveAction("alice", ZeroTrustAction.ALLOW, Map.of());

        RiskSignalReceiver.Receipt receipt = receiver.receive(token("jti-3", Map.of(
                SecurityEventToken.CREDENTIAL_CHANGE, Map.of("subject", Map.of("format", "phone_number",
                        "phone_number", "+10000000000")))));

        assertThat(receipt.subjects()).isEmpty();
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.ALLOW);
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordSync(record.capture());
        assertThat(record.getValue().getOutcome()).isEqualTo("UNKNOWN_SUBJECT");
        assertThat(RiskSignalReceiver.userOf(Map.of("format", "complex", "user", issSub("dave")), null))
                .isEqualTo("dave");
        assertThat(RiskSignalReceiver.userOf(Map.of("format", "opaque", "id", "erin"), null)).isEqualTo("erin");
    }

    @Test
    void aSignalNamingAPersonInTheFormOfAnInternalKeyStaysOffThatKey() {
        String own = ZeroTrustUserKey.person("console::admin");
        actions.saveAction("console::admin", ZeroTrustAction.ALLOW, Map.of());
        actions.saveAction(own, ZeroTrustAction.ALLOW, Map.of());

        receiver.receive(token("jti-5", Map.of(
                SecurityEventToken.TOKEN_CLAIMS_CHANGE, Map.of("subject", issSub("console::admin")))));

        assertThat(actions.getCurrentAction("console::admin")).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(actions.getCurrentAction(own)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void aRiskSignalOfContexaIsACaepRiskLevelChange() {
        RiskSignal signal = new RiskSignal(null, "alice", "report-agent", RiskSignal.LOW, RiskSignal.HIGH,
                ZeroTrustAction.BLOCK, "Export outside the delegation", Instant.ofEpochSecond(1_800_000_000L));

        Map<String, Object> claims = signal.caepClaims("https://contexa.test", "https://idp.test", "jti-9");

        assertThat(claims).containsEntry("iss", "https://contexa.test").containsEntry("aud", List.of("https://idp.test"))
                .containsEntry("jti", "jti-9").containsEntry("iat", 1_800_000_000L);
        assertThat(claims.get("sub_id")).isEqualTo(Map.of("format", "iss_sub", "iss", "https://contexa.test",
                "sub", "alice::agent::report-agent"));
        @SuppressWarnings("unchecked")
        Map<String, Object> event = (Map<String, Object>) ((Map<String, Object>) claims.get("events"))
                .get(SecurityEventToken.RISK_LEVEL_CHANGE);
        assertThat(event).containsEntry("principal", "AGENT").containsEntry("current_level", "HIGH")
                .containsEntry("previous_level", "LOW").containsEntry("risk_reason", "Export outside the delegation");
        assertThat(RiskSignal.levelOf(ZeroTrustAction.CHALLENGE)).isEqualTo(RiskSignal.MEDIUM);
        assertThat(RiskSignal.levelOf(ZeroTrustAction.PENDING_ANALYSIS)).isNull();
    }

    private static SecurityEventToken token(String jti, Map<String, Map<String, Object>> events) {
        return new SecurityEventToken("https://idp.test", jti, Instant.now(), null, events);
    }

    private static Map<String, Object> issSub(String sub) {
        return Map.of("format", "iss_sub", "iss", "https://idp.test", "sub", sub);
    }

    private List<AuditEventCategory> categories() {
        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, atLeastOnce()).recordSync(records.capture());
        return records.getAllValues().stream().map(AuditRecord::getEventCategory).toList();
    }
}
