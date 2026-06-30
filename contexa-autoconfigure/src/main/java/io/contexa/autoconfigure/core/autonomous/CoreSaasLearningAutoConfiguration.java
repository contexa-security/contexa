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

import io.contexa.contexacore.autonomous.saas.learning.registry.InMemoryLearningArtifactRegistryStore;
import io.contexa.contexacore.autonomous.saas.learning.registry.JpaLearningArtifactRegistryStore;
import io.contexa.contexacore.autonomous.saas.learning.registry.LearningArtifactRegistryService;
import io.contexa.contexacore.autonomous.saas.learning.registry.LearningArtifactRegistryStore;
import io.contexa.contexacore.autonomous.saas.learning.release.InMemoryLearningArtifactReleaseLedgerStore;
import io.contexa.contexacore.autonomous.saas.learning.release.JpaLearningArtifactReleaseLedgerStore;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerStore;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseService;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimeConflictService;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimePolicyService;
import io.contexa.contexacore.autonomous.saas.learning.roi.LearningRoiScoreboardService;
import io.contexa.contexacore.repository.LearningArtifactRegistryRecordRepository;
import io.contexa.contexacore.repository.LearningArtifactReleaseLedgerRecordRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@AutoConfigureBefore(name = "io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration")
@ConditionalOnProperty(prefix = "contexa.saas", name = "enabled", havingValue = "true")
public class CoreSaasLearningAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactRegistryStore learningArtifactRegistryStore(
            ObjectProvider<LearningArtifactRegistryRecordRepository> repositoryProvider) {
        LearningArtifactRegistryRecordRepository repository = repositoryProvider.getIfAvailable();
        if (repository != null) {
            return new JpaLearningArtifactRegistryStore(repository);
        }
        return new InMemoryLearningArtifactRegistryStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactRegistryService learningArtifactRegistryService(LearningArtifactRegistryStore store) {
        return new LearningArtifactRegistryService(store);
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactReleaseLedgerStore learningArtifactReleaseLedgerStore(
            ObjectProvider<LearningArtifactReleaseLedgerRecordRepository> repositoryProvider) {
        LearningArtifactReleaseLedgerRecordRepository repository = repositoryProvider.getIfAvailable();
        if (repository != null) {
            return new JpaLearningArtifactReleaseLedgerStore(repository);
        }
        return new InMemoryLearningArtifactReleaseLedgerStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactReleaseLedgerService learningArtifactReleaseLedgerService(
            LearningArtifactReleaseLedgerStore store,
            LearningArtifactRegistryService registryService) {
        return new LearningArtifactReleaseLedgerService(store, registryService);
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactReleaseService learningArtifactReleaseService() {
        return new LearningArtifactReleaseService();
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactRuntimePolicyService learningArtifactRuntimePolicyService() {
        return new LearningArtifactRuntimePolicyService();
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningArtifactRuntimeConflictService learningArtifactRuntimeConflictService(
            LearningArtifactReleaseLedgerService ledgerService,
            LearningArtifactRegistryService registryService) {
        return new LearningArtifactRuntimeConflictService(ledgerService, registryService);
    }

    @Bean
    @ConditionalOnMissingBean
    public LearningRoiScoreboardService learningRoiScoreboardService(
            LearningArtifactReleaseLedgerService ledgerService) {
        return new LearningRoiScoreboardService(ledgerService);
    }
}