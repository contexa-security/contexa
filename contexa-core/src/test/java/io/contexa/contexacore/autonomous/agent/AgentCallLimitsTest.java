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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent A5-7, F-1: an agent's calls are limited for its delegation and across the people it acts for; past a
 * limit it is slowed down or stopped; an agent refused unusually often raises an alarm; an ALLOW answers an agent's
 * later requests only for the same operation and a few resources. People and requests within the limits are as before.
 */
class AgentCallLimitsTest {

    private static final Instant NOW = Instant.parse("2026-10-24T04:00:00Z");
    private static final ZeroTrustSubject ALICE_AGENT = new ZeroTrustSubject(null, "alice",
            SubjectKind.DELEGATED_AGENT, "report-agent", null);
    private static final ZeroTrustSubject BOB_AGENT = new ZeroTrustSubject(null, "bob", SubjectKind.DELEGATED_AGENT,
            "report-agent", null);

    private final AgentConfirmationServiceTest.MovingClock clock = new AgentConfirmationServiceTest.MovingClock(NOW);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final InMemoryAgentNoticeStore notices = new InMemoryAgentNoticeStore();

    @Test
    void pastItsDelegationsLimitAnAgentIsSlowedDownAndWithinItNothingChanges() {
        AgentCallGuard guard = guard(limits(3, 100, SecurityZeroTrustProperties.CallLimit.OnExceed.THROTTLE));

        for (int call = 1; call <= 3; call++) {
            assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
        }
        AgentCallGuard.Admission refused = guard.admit(ALICE_AGENT, null);
        assertThat(refused.admitted()).isFalse();
        assertThat(refused.scope()).isEqualTo("DELEGATION");
        assertThat(refused.retryAfterSeconds()).isBetween(1L, 61L);
        assertThat(guard.recentCalls(ALICE_AGENT)).isEqualTo(4);
        // Another person's work with the same agent and the person themselves are not limited by it.
        assertThat(guard.admit(BOB_AGENT, null).admitted()).isTrue();
        assertThat(guard.admit(ZeroTrustSubject.person("alice"), null).admitted()).isTrue();
        // The slowdown is audited once a minute, not for every request.
        guard.admit(ALICE_AGENT, null);
        assertThat(categories()).containsExactly(AuditEventCategory.AGENT_CALL_LIMIT_EXCEEDED);

        clock.advance(Duration.ofSeconds(61));
        assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
    }

    /**
     * docs/agent CF-26: the wait the slowdown asks for is how long until enough of the counted calls leave the minute
     * for the next request to be within the limit, not only the oldest one; an agent that waits it is let on.
     */
    @Test
    void theWaitAskedForLetsTheNextRequestOnWhenMoreThanOneCallMustLeaveTheMinute() {
        AgentCallGuard guard = guard(limits(3, 100, SecurityZeroTrustProperties.CallLimit.OnExceed.THROTTLE));
        for (int call = 1; call <= 3; call++) {
            assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
            clock.advance(Duration.ofSeconds(10));
        }

        // Calls at 0, 10 and 20 s; the refused one at 30 s counts too, so the calls at 0 and 10 s must leave.
        AgentCallGuard.Admission refused = guard.admit(ALICE_AGENT, null);
        assertThat(refused.admitted()).isFalse();
        assertThat(refused.retryAfterSeconds()).isEqualTo(41);

        clock.advance(Duration.ofSeconds(refused.retryAfterSeconds() - 2));
        assertThat(guard.admit(ALICE_AGENT, null).admitted()).as("asked to wait longer").isFalse();
        AgentCallGuard.Admission waitingLonger = guard.admit(ALICE_AGENT, null);
        clock.advance(Duration.ofSeconds(waitingLonger.retryAfterSeconds()));
        assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
    }

    @Test
    void pastItsOwnLimitAcrossPeopleAnAgentIsStoppedWhenTheLimitStops() {
        AgentContainmentService containment = mock(AgentContainmentService.class);
        when(containment.onBlock(any(ZeroTrustSubject.class), any(), any(), anyString(), any()))
                .thenReturn(List.of("DELEGATION_REVOKED"));
        AgentCallGuard guard = guard(limits(100, 2, SecurityZeroTrustProperties.CallLimit.OnExceed.STOP));
        guard.setContainment(containment);

        assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
        assertThat(guard.admit(BOB_AGENT, null).admitted()).isTrue();
        AgentCallGuard.Admission refused = guard.admit(ALICE_AGENT, "report-client");

        assertThat(refused.admitted()).isFalse();
        assertThat(refused.scope()).isEqualTo("AGENT");
        verify(containment).onBlock(eq(ALICE_AGENT), eq("report-client"), isNull(), anyString(), isNull());
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordSync(record.capture());
        assertThat(record.getValue().getOutcome()).isEqualTo("STOPPED");
    }

    @Test
    void anAgentRefusedUnusuallyOftenRaisesAnAlarmOncePerWindow() {
        AgentCallGuard guard = guard(limits(100, 100, SecurityZeroTrustProperties.CallLimit.OnExceed.THROTTLE));
        for (int call = 0; call < 9; call++) {
            guard.outcome(ALICE_AGENT, call % 3 != 0);
        }
        assertThat(notices.list(null, 10)).isEmpty();

        guard.outcome(ALICE_AGENT, true);
        guard.outcome(ALICE_AGENT, true);

        assertThat(notices.forRecipient("alice", 10)).singleElement()
                .satisfies(notice -> assertThat(notice.kind()).isEqualTo(AgentNotice.DENIAL_RATE_ALARM));
        assertThat(categories()).containsExactly(AuditEventCategory.AGENT_DENIAL_RATE_ALARM);
        // An agent mostly let through raises none.
        for (int call = 0; call < 20; call++) {
            guard.outcome(BOB_AGENT, call % 5 == 0);
        }
        assertThat(notices.forRecipient("bob", 10)).isEmpty();
    }

    /** docs/agent G-9: in the report-only mode a passed limit is recorded as observed and nothing is slowed down. */
    @Test
    void inTheReportOnlyModeAPassedLimitIsObservedOnly() {
        AgentContainmentService containment = mock(AgentContainmentService.class);
        AgentCallGuard guard = guard(limits(1, 100, SecurityZeroTrustProperties.CallLimit.OnExceed.STOP));
        guard.setContainment(containment);
        guard.setEnforcing(() -> false);

        assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
        assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();

        verify(containment, never()).onBlock(any(ZeroTrustSubject.class), any(), any(), anyString(), any());
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordSync(record.capture());
        assertThat(record.getValue().getOutcome()).isEqualTo("OBSERVED");
    }

    @Test
    void offTheLimitsCountNothing() {
        SecurityZeroTrustProperties.CallLimit off = limits(1, 1, SecurityZeroTrustProperties.CallLimit.OnExceed.STOP);
        off.setEnabled(false);
        SecurityZeroTrustProperties.DenialAlarm noAlarm = new SecurityZeroTrustProperties.DenialAlarm();
        noAlarm.setEnabled(false);
        AgentCallGuard guard = new AgentCallGuard(off, noAlarm, new AgentNotices(notices, null), null, audit, clock);

        for (int call = 0; call < 5; call++) {
            assertThat(guard.admit(ALICE_AGENT, null).admitted()).isTrue();
            guard.outcome(ALICE_AGENT, true);
        }
        verify(audit, never()).recordSync(any());
    }

    @Test
    void anAllowAnswersAnAgentsRequestsOfTheSameOperationForAFewResources() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, clock);
        String key = ALICE_AGENT.storageKey();
        assertThat(reuse.answers(key, "ctx", ActionFamily.READ, "/api/customers/1")).isFalse();

        reuse.decided(key, "ctx", ActionFamily.READ, "/api/customers/1");

        assertThat(reuse.answers(key, "ctx", ActionFamily.READ, "/api/customers/1")).isTrue();
        assertThat(reuse.answers(key, "ctx", ActionFamily.READ, "/api/customers/2")).isTrue();
        assertThat(reuse.answers(key, "ctx", ActionFamily.READ, "/api/customers/3")).isTrue();
        // A fourth customer, another operation or another session is decided again.
        assertThat(reuse.answers(key, "ctx", ActionFamily.READ, "/api/customers/4")).isFalse();
        assertThat(reuse.answers(key, "ctx", ActionFamily.EXPORT, "/api/customers/1")).isFalse();
        assertThat(reuse.answers(key, "other-ctx", ActionFamily.READ, "/api/customers/1")).isFalse();

        AgentAllowReuse fewRequests = new AgentAllowReuse(2, 10, clock);
        fewRequests.decided(key, "ctx", ActionFamily.READ, "/api/a");
        assertThat(fewRequests.answers(key, "ctx", ActionFamily.READ, "/api/a")).isTrue();
        assertThat(fewRequests.answers(key, "ctx", ActionFamily.READ, "/api/a")).isFalse();
        assertThat(AgentAllowReuse.operation(Map.of("httpMethod", "GET", "requestPath", "/api/exports"), null))
                .isEqualTo(ActionFamily.EXPORT);
        assertThat(AgentAllowReuse.operation(Map.of("protectableMethod", "io.app.Customers.listCustomers"), null))
                .isEqualTo(ActionFamily.READ);
    }

    private AgentCallGuard guard(SecurityZeroTrustProperties.CallLimit limits) {
        return new AgentCallGuard(limits, new SecurityZeroTrustProperties.DenialAlarm(),
                new AgentNotices(notices, null), null, audit, clock);
    }

    private static SecurityZeroTrustProperties.CallLimit limits(int perDelegation, int perAgent,
                                                                SecurityZeroTrustProperties.CallLimit.OnExceed onExceed) {
        SecurityZeroTrustProperties.CallLimit limits = new SecurityZeroTrustProperties.CallLimit();
        limits.setPerDelegationPerMinute(perDelegation);
        limits.setPerAgentPerMinute(perAgent);
        limits.setOnExceed(onExceed);
        return limits;
    }

    private List<AuditEventCategory> categories() {
        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, atLeastOnce()).recordSync(records.capture());
        return records.getAllValues().stream().map(AuditRecord::getEventCategory).toList();
    }
}
