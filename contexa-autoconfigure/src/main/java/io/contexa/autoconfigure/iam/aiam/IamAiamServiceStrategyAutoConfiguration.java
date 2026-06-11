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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexaiam.aiam.service.DataIngestionServiceImpl;
import io.contexa.contexaiam.aiam.strategy.ConditionTemplateDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.PolicyGenerationDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.ResourceNamingDiagnosisStrategy;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
@AutoConfigureAfter(name = "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration")
public class IamAiamServiceStrategyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VectorStore.class)
    public DataIngestionServiceImpl dataIngestionService(
            VectorStore vectorStore,
            PolicyRepository policyRepository,
            ObjectMapper objectMapper) {
        return new DataIngestionServiceImpl(vectorStore, policyRepository, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateDiagnosisStrategy conditionTemplateDiagnosisStrategy(AILabFactory labFactory) {
        return new ConditionTemplateDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationDiagnosisStrategy policyGenerationDiagnosisStrategy(AILabFactory labFactory) {
        return new PolicyGenerationDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingDiagnosisStrategy resourceNamingDiagnosisStrategy(AILabFactory labFactory) {
        return new ResourceNamingDiagnosisStrategy(labFactory);
    }
}

