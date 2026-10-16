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

import io.contexa.contexacore.autonomous.tiered.strategy.AbstractTieredStrategy;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * W4-2: a security decision names no model, so the contextual and expert strategies judge native structured output by
 * the chat model the model selection picks; their beans hand them the model selection, taken when needed.
 */
class StrategyModelSelectionWiringTest {

    @Test
    void theContextualAndExpertStrategiesTakeTheModelSelection() throws Exception {
        ModelSelectionStrategy selection = mock(ModelSelectionStrategy.class);
        ObjectProvider<ModelSelectionStrategy> selectionProvider =
                new StaticListableBeanFactory(Map.of("modelSelectionStrategy", selection))
                        .getBeanProvider(ModelSelectionStrategy.class);
        CoreAutonomousAutoConfiguration configuration = new CoreAutonomousAutoConfiguration();

        for (String beanMethod : List.of("contextualStrategy", "expertStrategy")) {
            Method method = Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                    .filter(candidate -> candidate.getName().equals(beanMethod))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Method not found: " + beanMethod));
            Object[] arguments = new Object[method.getParameterCount()];
            for (int i = 0; i < arguments.length; i++) {
                arguments[i] = argument(method.getParameterTypes()[i], method.getGenericParameterTypes()[i],
                        selectionProvider);
            }

            AbstractTieredStrategy strategy = (AbstractTieredStrategy) method.invoke(configuration, arguments);

            Object handed = ReflectionTestUtils.getField(strategy, "modelSelectionStrategy");
            assertThat(handed).as(beanMethod).isInstanceOf(Supplier.class);
            assertThat(((Supplier<?>) handed).get()).as(beanMethod).isSameAs(selection);
        }
    }

    private static Object argument(Class<?> type, Type genericType, ObjectProvider<ModelSelectionStrategy> selection) {
        if (type == TieredStrategyProperties.class) {
            return new TieredStrategyProperties();
        }
        if (type == SecurityZeroTrustProperties.class) {
            return new SecurityZeroTrustProperties();
        }
        if (type == StructuredOutputCapabilityRegistry.class) {
            return StructuredOutputCapabilityRegistry.defaultRegistry();
        }
        if (type == ObjectProvider.class && genericType instanceof ParameterizedType parameterized
                && parameterized.getActualTypeArguments()[0] == ModelSelectionStrategy.class) {
            return selection;
        }
        return mock(type);
    }
}
