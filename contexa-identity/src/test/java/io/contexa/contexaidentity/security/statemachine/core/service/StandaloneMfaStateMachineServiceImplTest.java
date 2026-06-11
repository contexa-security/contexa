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
package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class StandaloneMfaStateMachineServiceImplTest {

    @Mock
    private StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;

    @Mock
    private StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;

    @Mock
    private InMemoryStateMachinePersist inMemoryStateMachinePersist;

    @Test
    @DisplayName("releaseStateMachine should delete persisted in-memory state")
    void releaseStateMachineDeletesPersistedState() {
        StandaloneMfaStateMachineServiceImpl service = new StandaloneMfaStateMachineServiceImpl(
                stateMachineFactory,
                stateMachinePersister,
                new StateMachineProperties(),
                inMemoryStateMachinePersist);

        service.releaseStateMachine("session-1");

        verify(inMemoryStateMachinePersist).delete("session-1");
    }
}
