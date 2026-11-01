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

import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the counts of delegations and agents that stopped calling are forgotten once their window has passed (a
 * minute for the call limits, the alarm window for the refusals), a few keys on each call and without waiting for
 * {@link AgentCallGuard#CAPACITY}; a count within its window is untouched.
 */
class AgentCallGuardIdleKeysTest {

    private static final Instant NOW = Instant.parse("2026-10-30T04:00:00Z");

    private final AgentConfirmationServiceTest.MovingClock clock = new AgentConfirmationServiceTest.MovingClock(NOW);

    @Test
    void theCountsOfDelegationsThatStoppedCallingAreForgottenAfterTheirWindow() {
        AgentCallGuard guard = guard(new SecurityZeroTrustProperties.CallLimit());
        for (int user = 0; user < 300; user++) {
            ZeroTrustSubject subject = agentFor("user-" + user);
            guard.admit(subject, null);
            guard.outcome(subject, false);
        }
        assertThat(guard.trackedCallKeys()).isEqualTo(301);
        assertThat(guard.trackedOutcomeKeys()).isEqualTo(300);

        clock.advance(Duration.ofMinutes(6));
        ZeroTrustSubject active = agentFor("active");
        for (int call = 0; call < 100; call++) {
            guard.admit(active, null);
            guard.outcome(active, false);
        }

        assertThat(guard.trackedCallKeys()).isEqualTo(2);
        assertThat(guard.trackedOutcomeKeys()).isEqualTo(1);
    }

    @Test
    void theReportTimesOfPassedLimitsAreForgottenAfterTheirInterval() {
        SecurityZeroTrustProperties.CallLimit limits = new SecurityZeroTrustProperties.CallLimit();
        limits.setPerDelegationPerMinute(1);
        AgentCallGuard guard = guard(limits);
        for (int user = 0; user < 50; user++) {
            ZeroTrustSubject subject = agentFor("user-" + user);
            guard.admit(subject, null);
            assertThat(guard.admit(subject, null).admitted()).isFalse();
        }
        assertThat(guard.trackedReportKeys()).isEqualTo(50);

        clock.advance(Duration.ofMinutes(6));
        ZeroTrustSubject active = agentFor("active");
        for (int call = 0; call < 100; call++) {
            guard.admit(active, null);
        }

        assertThat(guard.trackedReportKeys()).isEqualTo(1);
    }

    @Test
    void aDelegationsCallsWithinTheMinuteStayCounted() {
        AgentCallGuard guard = guard(new SecurityZeroTrustProperties.CallLimit());
        ZeroTrustSubject alice = agentFor("alice");
        for (int call = 0; call < 5; call++) {
            guard.admit(alice, null);
        }

        clock.advance(Duration.ofSeconds(30));
        for (int user = 0; user < 300; user++) {
            guard.admit(agentFor("user-" + user), null);
        }
        assertThat(guard.recentCalls(alice)).isEqualTo(5);

        clock.advance(Duration.ofSeconds(31));
        assertThat(guard.recentCalls(alice)).isZero();
    }

    private AgentCallGuard guard(SecurityZeroTrustProperties.CallLimit limits) {
        return new AgentCallGuard(limits, new SecurityZeroTrustProperties.DenialAlarm(), null, null, null, clock);
    }

    private static ZeroTrustSubject agentFor(String userId) {
        return new ZeroTrustSubject(null, userId, SubjectKind.DELEGATED_AGENT, "report-agent", null);
    }
}
