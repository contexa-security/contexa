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

import io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-83: the decision store learns what a stored ESCALATE ends as from the Layer2 settings, whichever store the
 * application runs on: the defaults end it as CHALLENGE, allow-escalate-final-action keeps it.
 */
class EscalateTerminalActionWiringTest {

    private static final Map<String, Object> FINAL = Map.of("observationId", "o-1", "processingGeneration", "g-1");

    @Test
    void theDefaultsEndAStoredEscalateAsChallenge() {
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
        repository.saveFinalAction("alice", ZeroTrustAction.ESCALATE, FINAL);

        bind(repository, new TieredStrategyProperties());

        assertThat(repository.getCurrentAction("alice", "context")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    void theConfiguredFallbackEndsAStoredEscalate() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setEscalateFallbackAction(ZeroTrustAction.ALLOW);
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
        repository.saveFinalAction("alice", ZeroTrustAction.ESCALATE, FINAL);

        bind(repository, properties);

        assertThat(repository.getActionFromHash("alice")).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    void allowEscalateFinalActionKeepsAStoredEscalate() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
        repository.saveFinalAction("alice", ZeroTrustAction.ESCALATE, FINAL);

        bind(repository, properties);

        assertThat(repository.getCurrentAction("alice", "context")).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    /** A store the application declares itself is told as well; the built-in ones are not the only ones bound. */
    @Test
    void aStoreTheApplicationDeclaresIsToldToo() {
        ZeroTrustActionRepository own = mock(ZeroTrustActionRepository.class);

        bind(own, new TieredStrategyProperties());

        verify(own).setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
    }

    @Test
    void anApplicationWithoutAStoreStarts() {
        ObjectProvider<ZeroTrustActionRepository> none =
                new DefaultListableBeanFactory().getBeanProvider(ZeroTrustActionRepository.class);

        new CoreAutonomousAutoConfiguration().contexaEscalateTerminalActionBinding(none, new TieredStrategyProperties())
                .afterSingletonsInstantiated();
    }

    /** The enforcement ends what no layer ended, by the same settings. */
    @Test
    void theEnforcementHandlerIsToldTheTerminalAction() throws Exception {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setEscalateFallbackAction(ZeroTrustAction.BLOCK);

        Object handler = invoke(new CoreAutonomousEventAutoConfiguration(), "securityDecisionEnforcementHandler", properties);

        assertThat(ReflectionTestUtils.getField(handler, "escalateTerminalAction")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    void theEnforcementHandlerKeepsAnAllowedFinalEscalate() throws Exception {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);

        Object handler = invoke(new CoreAutonomousEventAutoConfiguration(), "securityDecisionEnforcementHandler", properties);

        assertThat(ReflectionTestUtils.getField(handler, "escalateTerminalAction")).isNull();
    }

    /** The access filter never promotes under the defaults, and keeps the promotion with the setting on. */
    @Test
    void theAccessFilterIsToldTheTerminalAction() throws Exception {
        Object filter = invoke(new IdentitySecurityCoreAutoConfiguration(), "zeroTrustAccessControlFilter",
                new TieredStrategyProperties());

        assertThat(ReflectionTestUtils.getField(filter, "escalateTerminalAction")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    void theAccessFilterKeepsThePromotionWithAnAllowedFinalEscalate() throws Exception {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);

        Object filter = invoke(new IdentitySecurityCoreAutoConfiguration(), "zeroTrustAccessControlFilter", properties);

        assertThat(ReflectionTestUtils.getField(filter, "escalateTerminalAction")).isNull();
    }

    private static void bind(ZeroTrustActionRepository repository, TieredStrategyProperties properties) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("repository", repository);
        SmartInitializingSingleton binding = new CoreAutonomousAutoConfiguration().contexaEscalateTerminalActionBinding(
                beans.getBeanProvider(ZeroTrustActionRepository.class), properties);
        binding.afterSingletonsInstantiated();
    }

    /** Calls the bean method with the properties for their types and mocks for the rest. */
    private static Object invoke(Object configuration, String name, TieredStrategyProperties properties) throws Exception {
        Method method = Arrays.stream(configuration.getClass().getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Bean method not found: " + name));
        Object[] arguments = new Object[method.getParameterCount()];
        for (int i = 0; i < arguments.length; i++) {
            Class<?> type = method.getParameterTypes()[i];
            arguments[i] = type == SecurityZeroTrustProperties.class ? new SecurityZeroTrustProperties()
                    : type == TieredStrategyProperties.class ? properties
                    : type == ObjectProvider.class ? provider(method.getGenericParameterTypes()[i], properties)
                    : mock(type);
        }
        return method.invoke(configuration, arguments);
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<Object> provider(Type type, TieredStrategyProperties properties) {
        ObjectProvider<Object> provider = mock(ObjectProvider.class);
        Type provided = type instanceof ParameterizedType parameterized ? parameterized.getActualTypeArguments()[0] : null;
        if (provided == TieredStrategyProperties.class) {
            when(provider.getIfAvailable(any())).thenReturn(properties);
        } else {
            when(provider.orderedStream()).thenAnswer(call -> Stream.empty());
        }
        return provider;
    }
}
