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

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexaiam.aiam.components.prompt.*;
import io.contexa.contexaiam.aiam.components.retriever.*;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAiamComponentsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationTemplate policyGenerationTemplate() {
        return new PolicyGenerationTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationStreamingTemplate policyGenerationStreamingTemplate() {
        return new PolicyGenerationStreamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingTemplate resourceNamingTemplate() {
        return new ResourceNamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplatePromptTemplate conditionTemplatePromptTemplate() {
        return new ConditionTemplatePromptTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class, PolicyGenerationVectorService.class, ContexaRagProperties.class})
    public PolicyGenerationContextRetriever policyGenerationContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            PolicyGenerationVectorService policyGenerationVectorService,
            ContexaRagProperties ragProperties) {
        return new PolicyGenerationContextRetriever(
                vectorStore, contextRetrieverRegistry, policyGenerationVectorService, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class, ContexaRagProperties.class})
    public ConditionTemplateContextRetriever conditionTemplateContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        return new ConditionTemplateContextRetriever(
                vectorStore, contextRetrieverRegistry, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class, ContexaRagProperties.class})
    public ResourceNamingContextRetriever resourceNamingContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        return new ResourceNamingContextRetriever(
                vectorStore, contextRetrieverRegistry, ragProperties);
    }
}

