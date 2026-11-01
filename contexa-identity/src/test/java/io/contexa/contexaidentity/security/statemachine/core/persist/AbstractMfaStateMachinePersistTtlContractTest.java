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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (4.3, F6): the MFA state machine context of an abandoned flow lapses in either mode, the persistence TTL
 * ({@code contexa.identity.statemachine.persistence.ttl-minutes}) after its last write; a read does not keep it.
 */
abstract class AbstractMfaStateMachinePersistTtlContractTest {

    protected final List<String> writtenIds = new ArrayList<>();

    /** A persist of the mode whose contexts lapse {@code ttl} after their last write. */
    protected abstract void usePersist(Duration ttl);

    protected abstract void write(StateMachineContext<MfaState, MfaEvent> context, String id) throws Exception;

    protected abstract StateMachineContext<MfaState, MfaEvent> read(String id) throws Exception;

    @Test
    void aContextLastsTheTtlFromItsLastWrite() throws Exception {
        usePersist(Duration.ofSeconds(2));
        String id = id();
        write(context(MfaState.AWAITING_FACTOR_SELECTION), id);

        Thread.sleep(1_200);
        write(context(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION), id);
        Thread.sleep(1_200);
        assertThat(read(id)).as("within the TTL of the last write").isNotNull()
                .extracting(StateMachineContext::getState).isEqualTo(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);

        Thread.sleep(1_200);
        assertThat(read(id)).isNull();
    }

    @Test
    void aReadDoesNotKeepTheContext() throws Exception {
        usePersist(Duration.ofSeconds(2));
        String id = id();
        write(context(MfaState.AWAITING_FACTOR_SELECTION), id);

        Thread.sleep(1_200);
        assertThat(read(id)).isNotNull();
        Thread.sleep(1_200);

        assertThat(read(id)).isNull();
    }

    private String id() {
        String id = "z16-mfa-" + UUID.randomUUID();
        writtenIds.add(id);
        return id;
    }

    private static StateMachineContext<MfaState, MfaEvent> context(MfaState state) {
        return new DefaultStateMachineContext<>(state, null, null, new DefaultExtendedState(), null, "mfa");
    }
}
