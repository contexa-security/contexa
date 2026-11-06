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
package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.serializers.DefaultSerializers;
import com.esotericsoftware.kryo.serializers.FieldSerializer;
import com.esotericsoftware.kryo.util.DefaultInstantiatorStrategy;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.objenesis.strategy.StdInstantiatorStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.kryo.KryoStateMachineSerialisationService;
import org.springframework.statemachine.kryo.StateMachineContextSerializer;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.statemachine.support.ObservableMap;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * What a distributed deployment keeps of an MFA flow. The fields of the flow are Contexa's own and are stored by value.
 * Its two open fields hold what belongs to the application, and neither decides whether a flow can be restored (PR-80):
 * of the sign-in only the facts the flow reads are kept ({@link MinimalAuthenticationSerializer}), and each attribute is
 * kept on its own ({@link FactorContextAttributesSerializer}). A user who cannot restore the flow cannot answer a
 * CHALLENGE, so no object of the application may be able to stop it.
 */
public class MfaKryoStateMachineSerialisationService extends KryoStateMachineSerialisationService<MfaState, MfaEvent> {

    @Override
    protected void configureKryoInstance(Kryo kryo) {
        configureTypes(kryo);

        Kryo attributeValues = new Kryo();
        attributeValues.setClassLoader(kryo.getClassLoader());
        configureTypes(attributeValues);

        kryo.register(FactorContext.class, factorContextSerializer(kryo, attributeValues));
    }

    private void configureTypes(Kryo kryo) {

        super.configureKryoInstance(kryo);
        configureValueTypes(kryo);
        kryo.register(DefaultStateMachineContext.class);
        kryo.register(DefaultExtendedState.class);
        kryo.register(FactorContext.MfaAttemptDetail.class);
        kryo.register(StateConfig.class);
        kryo.register(StateType.class, new DefaultSerializers.EnumSerializer(StateType.class));
        
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
        kryo.register(AuthType.class);
        kryo.register(Instant.class);
        kryo.addDefaultSerializer(DefaultStateMachineContext.class, new StateMachineContextSerializer<MfaState, MfaEvent>());
    }

    /**
     * How a value of any type is made and read. The read-only views of {@link Collections} are added here because
     * Kryo's readers would refill them; Kryo itself covers the empty, singleton and {@code List.of} kinds and
     * {@code Arrays.asList}.
     */
    private static void configureValueTypes(Kryo kryo) {
        kryo.setInstantiatorStrategy(new DefaultInstantiatorStrategy(new StdInstantiatorStrategy()));
        kryo.setRegistrationRequired(false);
        kryo.addDefaultSerializer(Authentication.class, new MinimalAuthenticationSerializer());
        kryo.addDefaultSerializer(Collections.unmodifiableCollection(new ArrayList<>()).getClass(),
                new UnmodifiableListSerializer());
        kryo.addDefaultSerializer(Collections.unmodifiableList(new LinkedList<>()).getClass(),
                new UnmodifiableListSerializer());
        kryo.addDefaultSerializer(Collections.unmodifiableSet(new HashSet<>()).getClass(),
                new UnmodifiableSetSerializer());
        kryo.addDefaultSerializer(Collections.unmodifiableMap(new HashMap<>()).getClass(),
                new UnmodifiableMapSerializer());
    }

    /**
     * The value class of the sign-in is fixed, so the class of the application's authentication is not written either:
     * a reader that cannot load it would fail before any serializer is asked.
     */
    private static FieldSerializer<FactorContext> factorContextSerializer(Kryo kryo, Kryo attributeValues) {
        FieldSerializer<FactorContext> serializer = new FieldSerializer<>(kryo, FactorContext.class);
        serializer.getField("primaryAuthentication")
                .setValueClass(Authentication.class, new MinimalAuthenticationSerializer());
        serializer.getField("attributes")
                .setValueClass(Map.class, new FactorContextAttributesSerializer(attributeValues));
        return serializer;
    }
}
