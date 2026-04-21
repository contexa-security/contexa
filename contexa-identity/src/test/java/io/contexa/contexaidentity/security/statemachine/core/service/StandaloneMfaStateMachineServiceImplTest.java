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
