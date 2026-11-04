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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAiamComponentsAutoConfiguration {

    @Bean(name = "contexaPolicyGenerationTemplate")
    @ConditionalOnMissingBean
    public PolicyGenerationTemplate policyGenerationTemplate() {
        return new PolicyGenerationTemplate();
    }

    @Bean(name = "contexaPolicyGenerationStreamingTemplate")
    @ConditionalOnMissingBean
    public PolicyGenerationStreamingTemplate policyGenerationStreamingTemplate() {
        return new PolicyGenerationStreamingTemplate();
    }

    @Bean(name = "contexaResourceNamingTemplate")
    @ConditionalOnMissingBean
    public ResourceNamingTemplate resourceNamingTemplate() {
        return new ResourceNamingTemplate();
    }

    @Bean(name = "contexaConditionTemplatePromptTemplate")
    @ConditionalOnMissingBean
    public ConditionTemplatePromptTemplate conditionTemplatePromptTemplate() {
        return new ConditionTemplatePromptTemplate();
    }

    @Bean(name = "contexaPolicyGenerationContextRetriever")
    @ConditionalOnMissingBean
    @ConditionalOnBean(value = {ContextRetrieverRegistry.class, PolicyGenerationVectorService.class, ContexaRagProperties.class}, name = "contexaVectorStore")
    public PolicyGenerationContextRetriever policyGenerationContextRetriever(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            ContextRetrieverRegistry contexaContextRetrieverRegistry,
            PolicyGenerationVectorService contexaPolicyGenerationVectorService,
            ContexaRagProperties ragProperties) {
        return new PolicyGenerationContextRetriever(
                vectorStore, contexaContextRetrieverRegistry, contexaPolicyGenerationVectorService, ragProperties);
    }

    @Bean(name = "contexaConditionTemplateContextRetriever")
    @ConditionalOnMissingBean
    @ConditionalOnBean(value = {ContextRetrieverRegistry.class, ContexaRagProperties.class}, name = "contexaVectorStore")
    public ConditionTemplateContextRetriever conditionTemplateContextRetriever(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            ContextRetrieverRegistry contexaContextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        return new ConditionTemplateContextRetriever(
                vectorStore, contexaContextRetrieverRegistry, ragProperties);
    }

    @Bean(name = "contexaResourceNamingContextRetriever")
    @ConditionalOnMissingBean
    @ConditionalOnBean(value = {ContextRetrieverRegistry.class, ContexaRagProperties.class}, name = "contexaVectorStore")
    public ResourceNamingContextRetriever resourceNamingContextRetriever(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            ContextRetrieverRegistry contexaContextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        return new ResourceNamingContextRetriever(
                vectorStore, contexaContextRetrieverRegistry, ragProperties);
    }
}

