package io.contexa.contexaidentity.security.statemachine.core.persist;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class InMemoryStateMachinePersist implements StateMachinePersist<MfaState, MfaEvent, String> {

    private final Map<String, StateMachineContext<MfaState, MfaEvent>> storage = new ConcurrentHashMap<>();

    private static final String KEY_PREFIX = "mfa:statemachine:";

    @Override
    public void write(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
        String key = KEY_PREFIX + contextObj;
        
        storage.put(key, context);

            }

    @Override
    public StateMachineContext<MfaState, MfaEvent> read(String contextObj) throws Exception {
        String key = KEY_PREFIX + contextObj;
        
        StateMachineContext<MfaState, MfaEvent> context = storage.get(key);

        if (context != null) {
                    } else {
                    }

        return context;
    }

    public void delete(String contextObj) {
        String key = KEY_PREFIX + contextObj;
        
        storage.remove(key);
    }
}