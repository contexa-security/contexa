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
package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaiam.aiam.components.prompt.ConditionTemplatePromptTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationStreamingTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationTemplate;
import io.contexa.contexaiam.aiam.components.prompt.ResourceNamingTemplate;
import io.contexa.contexaiam.aiam.components.retriever.ConditionTemplateContextRetriever;
import io.contexa.contexaiam.aiam.components.retriever.PolicyGenerationContextRetriever;
import io.contexa.contexaiam.aiam.components.retriever.ResourceNamingContextRetriever;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IamAiamComponentsAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamAiamComponentsAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> mock(PlatformConfig.class));

    @Test
    void shouldCreatePromptTemplatesWithoutVectorStore() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(PolicyGenerationTemplate.class);
            assertThat(context).hasSingleBean(PolicyGenerationStreamingTemplate.class);
            assertThat(context).hasSingleBean(ResourceNamingTemplate.class);
            assertThat(context).hasSingleBean(ConditionTemplatePromptTemplate.class);
        });
    }

    @Test
    void shouldBackOffVectorRetrieversWhenVectorStoreIsNotConfigured() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(PolicyGenerationContextRetriever.class);
            assertThat(context).doesNotHaveBean(ConditionTemplateContextRetriever.class);
            assertThat(context).doesNotHaveBean(ResourceNamingContextRetriever.class);
        });
    }
}
