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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * docs/agent A3-8: the control of what an agent learned is a bean of the core configuration on the security context
 * store, and the baseline learning reads the quarantine it keeps.
 */
class AgentLearningControlWiringTest {

    private final CoreAutonomousAutoConfiguration configuration = new CoreAutonomousAutoConfiguration();
    private final InMemorySecurityContextDataStore contextStore = new InMemorySecurityContextDataStore();
    private final InMemoryBaselineDataStore baselineStore = new InMemoryBaselineDataStore(Duration.ofDays(30));

    @Test
    void aQuarantineTakenByTheControlKeepsTheBaselineOfTheAgentFromBeingRead() {
        AgentLearningControl control = configuration.agentLearningControl(provider(contextStore),
                provider(baselineStore), provider(null));
        BaselineLearningService learning = configuration.baselineLearningService(baselineStore,
                new SecurityZeroTrustProperties(), provider(null), provider(contextStore));
        baselineStore.saveUserBaseline("alice::agent::agt-1", BaselineVector.builder().userId("alice")
                .updateCount(3L).build());
        SecurityEvent agent = SecurityEvent.builder().userId("alice").build();
        agent.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        agent.addMetadata("agentId", "agt-1");

        assertThat(learning.getPersonalBaseline("alice", agent)).isNotNull();
        control.quarantine("agt-1", null);

        assertThat(learning.getPersonalBaseline("alice", agent)).isNull();
        // Without a vector store the records cannot be quarantined, and nothing fails for it.
        assertThat(control.quarantine("agt-1", null).records()).isZero();
    }

    @Test
    void withoutASecurityContextStoreTheControlRefusesAndTheLearningGoesOn() {
        AgentLearningControl control = configuration.agentLearningControl(provider(null), provider(null),
                provider(null));

        assertThat(control.quarantined("agt-1", null)).isFalse();
        assertThat(configuration.baselineLearningService(mock(BaselineDataStore.class),
                new SecurityZeroTrustProperties(), provider(null), provider(null))).isNotNull();
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }
}
