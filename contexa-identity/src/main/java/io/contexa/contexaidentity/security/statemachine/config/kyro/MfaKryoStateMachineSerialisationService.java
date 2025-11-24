package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.serializers.DefaultSerializers;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.service.CustomUserDetails;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexacommon.entity.Users;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.statemachine.kryo.KryoStateMachineSerialisationService;
import org.springframework.statemachine.kryo.StateMachineContextSerializer;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.statemachine.support.ObservableMap;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class MfaKryoStateMachineSerialisationService extends KryoStateMachineSerialisationService<MfaState, MfaEvent> {

    @Override
    protected void configureKryoInstance(Kryo kryo) {

        super.configureKryoInstance(kryo);
        kryo.setRegistrationRequired(false);
        kryo.register(DefaultStateMachineContext.class);
        kryo.register(DefaultExtendedState.class);
        kryo.register(FactorContext.class);
        kryo.register(StateConfig.class);
        kryo.register(StateType.class, new DefaultSerializers.EnumSerializer(StateType.class));
        // Phase 3.4: MfaDecision은 FactorContext에 저장하지 않으므로 등록 불필요
        if (MfaState.class.isEnum()) {
            kryo.register(MfaState.class, new DefaultSerializers.EnumSerializer(MfaState.class));
        }
        if (MfaEvent.class.isEnum()) {
            kryo.register(MfaEvent.class, new DefaultSerializers.EnumSerializer(MfaEvent.class));
        }

        kryo.register(HashMap.class);
        kryo.register(ArrayList.class);
        kryo.register(LinkedHashMap.class); 
        kryo.register(ObservableMap.class); 
        kryo.register(ConcurrentHashMap.class); 
        kryo.register(CopyOnWriteArrayList.class); 
        kryo.register(AtomicReference.class, new AtomicReferenceSerializer());
        kryo.register(AtomicInteger.class, new AtomicIntegerSerializer()); 
        kryo.register(Authentication.class); 
        kryo.register(AuthType.class); 
        kryo.register(Instant.class); 
        kryo.register(UsernamePasswordAuthenticationToken.class); 
        try {
            Class<?> unmodifiableListClass = Collections.unmodifiableList(new ArrayList<>()).getClass();
            kryo.register(unmodifiableListClass, new UnmodifiableListSerializer());
            Class<?> emptyListClass = Collections.emptyList().getClass();
            if (kryo.getRegistration(emptyListClass) == null) {
                kryo.register(emptyListClass);
            }
        } catch (Exception e) {
            log.error("Failed to register unmodifiable collection types for Kryo", e);
        }
        kryo.register(SimpleGrantedAuthority.class);
        kryo.register(CustomUserDetails.class);
        kryo.register(Users.class);
        kryo.addDefaultSerializer(DefaultStateMachineContext.class, new StateMachineContextSerializer<MfaState, MfaEvent>());
    }
}
