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
package io.contexa.autoconfigure.core.std;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class CoreStdComponentsContextRetrieverGuardTest {

    @Test
    @DisplayName("contextRetriever does not require UnifiedVectorService directly")
    void contextRetrieverDoesNotRequireUnifiedVectorServiceDirectly() throws Exception {
        Method method = CoreStdComponentsAutoConfiguration.class.getDeclaredMethod(
                "contextRetriever",
                ObjectProvider.class,
                ContexaRagProperties.class,
                PromptContextAuthorizationService.class);

        assertThat(method.toGenericString()).contains("ObjectProvider<io.contexa.contexacore.std.rag.service.UnifiedVectorService>");
    }
}