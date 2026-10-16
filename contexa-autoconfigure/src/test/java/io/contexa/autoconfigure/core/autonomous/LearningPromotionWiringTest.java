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

import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * W5-1: the learning promotion is a bean of the core configuration and reaches what holds and promotes: the enforcement
 * handler, the learning after a step-up and the past records (with the host's promotion settings).
 */
class LearningPromotionWiringTest {

    private final LearningPromotionService promotion = mock(LearningPromotionService.class);
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();

    @Test
    void theCoreConfigurationMakesTheLearningPromotion() throws Exception {
        Object bean = invoke(new CoreAutonomousAutoConfiguration(), "learningPromotionService");

        assertThat(bean).isInstanceOf(LearningPromotionService.class);
    }

    @Test
    void theHandlerTheStepUpLearningAndThePastRecordsReachThePromotion() throws Exception {
        properties.getBaseline().getPromotion().setMinResourceClass("CRITICAL");

        Object handler = invoke(new CoreAutonomousEventAutoConfiguration(), "securityDecisionEnforcementHandler");
        Object verification = invoke(new CoreAutonomousAutoConfiguration(), "verificationLearningService");
        Object postProcessor = invoke(new CoreAutonomousAutoConfiguration(), "securityDecisionPostProcessor");

        assertThat(ReflectionTestUtils.getField(handler, "learningPromotionService")).isSameAs(promotion);
        assertThat(ReflectionTestUtils.getField(verification, "learningPromotionService")).isSameAs(promotion);
        assertThat(ReflectionTestUtils.getField(postProcessor, "learningPromotionSettings"))
                .isEqualTo(new LearningPromotionPolicy.Settings(true, "CRITICAL", 2, 2, true));
    }

    /** Calls the bean method with the promotion and properties for their types and mocks for the rest. */
    private Object invoke(Object configuration, String name) throws Exception {
        Method method = Arrays.stream(configuration.getClass().getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Bean method not found: " + name));
        Object[] arguments = new Object[method.getParameterCount()];
        for (int i = 0; i < arguments.length; i++) {
            Class<?> type = method.getParameterTypes()[i];
            arguments[i] = type == SecurityZeroTrustProperties.class ? properties
                    : type == ObjectProvider.class ? provider(method.getGenericParameterTypes()[i])
                    : mock(type);
        }
        return method.invoke(configuration, arguments);
    }

    @SuppressWarnings("unchecked")
    private ObjectProvider<Object> provider(Type type) {
        ObjectProvider<Object> provider = mock(ObjectProvider.class);
        Type provided = type instanceof ParameterizedType parameterized ? parameterized.getActualTypeArguments()[0] : null;
        if (provided == LearningPromotionService.class) {
            when(provider.getIfAvailable()).thenReturn(promotion);
        }
        if (provided == SecurityZeroTrustProperties.class) {
            when(provider.getIfAvailable()).thenReturn(properties);
        }
        when(provider.getIfAvailable(any())).thenAnswer(call -> provider.getIfAvailable());
        return provider;
    }
}
