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

import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class CoreAutonomousPostProcessorGuardTest {

    @Test
    @DisplayName("securityDecisionPostProcessor requires UnifiedVectorService")
    void securityDecisionPostProcessorRequiresUnifiedVectorService() throws Exception {
        Method method = CoreAutonomousAutoConfiguration.class
                .getDeclaredMethod("securityDecisionPostProcessor", SecurityContextDataStore.class, UnifiedVectorService.class);

        assertThat(method.getReturnType()).isEqualTo(SecurityDecisionPostProcessor.class);
        ConditionalOnBean annotation = method.getAnnotation(ConditionalOnBean.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.value()).containsExactly(UnifiedVectorService.class);
    }
}