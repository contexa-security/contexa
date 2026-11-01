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

import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * QF-32: the default infrastructure mode keeps the learned state in memory; when standalone selects the in-memory
 * baseline, observation and hold stores, one warning at startup says that what is learned is lost on restart.
 */
@ExtendWith(OutputCaptureExtension.class)
class StandaloneLearningStateWarningTest {

    private static final String WARNING = "learned state is kept in memory and lost on restart";

    @Test
    void theStandaloneModeWarnsOnceThatTheLearnedStateIsLostOnRestart(CapturedOutput output) throws Exception {
        Method method = beanMethod("standaloneLearningStateWarning");
        ConditionalOnProperty condition = method.getAnnotation(ConditionalOnProperty.class);
        assertThat(condition).isNotNull();
        assertThat(condition.name()).containsExactly("contexa.infrastructure.mode");
        assertThat(condition.havingValue()).isEqualTo("standalone");
        assertThat(condition.matchIfMissing()).isTrue();

        SmartInitializingSingleton warning = (SmartInitializingSingleton) method.invoke(
                new CoreAutonomousAutoConfiguration(), provider(new InMemoryBaselineDataStore()),
                provider(new InMemorySecurityContextDataStore()));
        warning.afterSingletonsInstantiated();

        assertThat(output).containsOnlyOnce(WARNING);
        assertThat(output).contains("InMemoryBaselineDataStore").contains("InMemorySecurityContextDataStore");
    }

    @Test
    void storesTheHostGivesKeepTheStartupSilent(CapturedOutput output) throws Exception {
        SmartInitializingSingleton warning = (SmartInitializingSingleton) beanMethod("standaloneLearningStateWarning")
                .invoke(new CoreAutonomousAutoConfiguration(), provider(mock(BaselineDataStore.class)),
                        provider(mock(SecurityContextDataStore.class)));
        warning.afterSingletonsInstantiated();

        assertThat(output).doesNotContain(WARNING);
    }

    private static Method beanMethod(String name) {
        return Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Bean method not found: " + name));
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T bean) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(bean);
        return provider;
    }
}
