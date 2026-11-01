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
package io.contexa.contexaidentity.security.statemachine.core.persist;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.Test;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryStateMachinePersistTtlContractTest extends AbstractMfaStateMachinePersistTtlContractTest {

    private InMemoryStateMachinePersist persist;

    @Override
    protected void usePersist(Duration ttl) {
        persist = new InMemoryStateMachinePersist(ttl);
    }

    @Override
    protected void write(StateMachineContext<MfaState, MfaEvent> context, String id) throws Exception {
        persist.write(context, id);
    }

    @Override
    protected StateMachineContext<MfaState, MfaEvent> read(String id) throws Exception {
        return persist.read(id);
    }

    @Test
    void theSweepReleasesALapsedContext() throws Exception {
        usePersist(Duration.ofMillis(300));
        persist.write(new DefaultStateMachineContext<>(MfaState.AWAITING_FACTOR_SELECTION, null, null,
                new DefaultExtendedState(), null, "mfa"), "z16-mfa-swept");
        persist.removeExpiredEntries();
        assertThat(persist.holdsContextFor("z16-mfa-swept")).isTrue();

        Thread.sleep(500);
        persist.removeExpiredEntries();

        assertThat(persist.holdsContextFor("z16-mfa-swept")).isFalse();
    }
}
