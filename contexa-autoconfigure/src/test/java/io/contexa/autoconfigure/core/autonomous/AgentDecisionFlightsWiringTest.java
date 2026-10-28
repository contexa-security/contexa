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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** RL-12: the settings of contexa.security.zerotrust.agent.flight reach the flights. */
class AgentDecisionFlightsWiringTest {

    private static AgentDecisionFlights flightsOf(SecurityZeroTrustProperties properties) {
        return new CoreAutonomousEventAutoConfiguration().agentDecisionFlights(properties);
    }

    @Test
    void byDefaultTheFlightsAreOffAndHoldThePlannedLimits() {
        AgentDecisionFlights flights = flightsOf(new SecurityZeroTrustProperties());

        assertThat(flights.enabled()).isFalse();
        AgentDecisionFlights.Settings settings = flights.settings();
        assertThat(settings.maxInFlightAnalyses()).isEqualTo(3);
        assertThat(settings.queueCapacity()).isEqualTo(20);
        assertThat(settings.maxWait()).isEqualTo(Duration.ofSeconds(40));
        assertThat(settings.passBudget()).isEqualTo(3);
        assertThat(settings.passFamilies()).containsExactly(ActionFamily.READ);
    }

    @Test
    void theApplicationSetsEveryLimit() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        SecurityZeroTrustProperties.Flight flight = properties.getAgent().getFlight();
        flight.setEnabled(true);
        flight.setMaxInFlightAnalyses(5);
        flight.setQueueCapacity(7);
        flight.setWait(Duration.ofSeconds(2));
        flight.setPassBudget(0);
        flight.setPassFamilies(List.of("read", "LIST", "no-such-family"));

        AgentDecisionFlights.Settings settings = flightsOf(properties).settings();

        assertThat(settings.enabled()).isTrue();
        assertThat(settings.maxInFlightAnalyses()).isEqualTo(5);
        assertThat(settings.queueCapacity()).isEqualTo(7);
        assertThat(settings.maxWait()).isEqualTo(Duration.ofSeconds(2));
        assertThat(settings.passBudget()).isZero();
        // a name that names no family is dropped, never read as a family it does not name
        assertThat(settings.passFamilies()).isSubsetOf(Set.of(ActionFamily.READ)).contains(ActionFamily.READ);
    }
}
