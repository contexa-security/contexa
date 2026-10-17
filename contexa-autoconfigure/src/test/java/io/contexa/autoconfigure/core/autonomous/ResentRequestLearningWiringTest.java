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

import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
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
 * N-LRN-3: the recorder of the requests that reached no analysis reaches the learning after a verification, which
 * learns the first request sent again after a passed step-up of those a web filter stopped under the challenge.
 */
class ResentRequestLearningWiringTest {

    private final VerificationLearningService verification = mock(VerificationLearningService.class);

    @Test
    void theUnanalysedRequestRecorderReachesTheVerificationLearning() throws Exception {
        Object recorder = invoke(new CoreAutonomousAutoConfiguration(), "unanalysedRequestRecorder");

        assertThat(recorder).isInstanceOf(UnanalysedRequestRecorder.class);
        assertThat(ReflectionTestUtils.getField(recorder, "verificationLearningService")).isSameAs(verification);
    }

    /** Calls the bean method with the verification learning for its type and mocks for the rest. */
    private Object invoke(Object configuration, String name) throws Exception {
        Method method = Arrays.stream(configuration.getClass().getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Bean method not found: " + name));
        Object[] arguments = new Object[method.getParameterCount()];
        for (int i = 0; i < arguments.length; i++) {
            Class<?> type = method.getParameterTypes()[i];
            arguments[i] = type == ObjectProvider.class ? provider(method.getGenericParameterTypes()[i]) : mock(type);
        }
        return method.invoke(configuration, arguments);
    }

    @SuppressWarnings("unchecked")
    private ObjectProvider<Object> provider(Type type) {
        ObjectProvider<Object> provider = mock(ObjectProvider.class);
        Type provided = type instanceof ParameterizedType parameterized
                ? parameterized.getActualTypeArguments()[0] : null;
        if (provided == VerificationLearningService.class) {
            when(provider.getIfAvailable()).thenReturn(verification);
        }
        when(provider.getIfAvailable(any())).thenAnswer(call -> provider.getIfAvailable());
        return provider;
    }
}
