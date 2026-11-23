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
package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplayApiController;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import java.util.function.Supplier;

/**
 * The replay of sealed decisions (docs/agent OC-5): a sealed decision drawn again with a chosen version and asked once,
 * and the admin API that asks for one. The prompt version trials and the finished prompt of the version screen stand on
 * it, so it is wired wherever the sealed packages are kept, whether the prompt inspection
 * ({@code contexa.prompt-inspection.enabled}) is on or off. Enterprise keeps sealed packages in its own schema, so none
 * of these beans are created while Enterprise is enabled.
 */
@AutoConfiguration(after = {PromptGovernanceAutoConfiguration.class, SealedEvidenceStoreAutoConfiguration.class,
        PqaSealedEvidenceAutoConfiguration.class})
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
public class SealedDecisionReplayAutoConfiguration {

    /**
     * docs/agent OC-5: the operator's replay of a sealed decision with a chosen bundle, through the engine's prompt
     * template and pipeline; without them the replay API answers that the replay is not available.
     */
    @Bean(name = "contexaSealedDecisionReplays")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SealedEvidencePackageRepository.class)
    public SealedDecisionReplays sealedDecisionReplays(
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            ObjectProvider<SecurityDecisionStandardPromptTemplate> templates,
            ObjectProvider<PipelineOrchestrator> pipelines,
            ObjectProvider<BaselineLearningService> baselineLearning,
            ObjectProvider<TieredStrategyProperties> tieredProperties,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustProperties,
            ObjectProvider<StructuredOutputCapabilityRegistry> structuredOutput,
            ObjectProvider<ModelSelectionStrategy> modelSelection,
            ObjectProvider<CanonicalSecurityContextSerializer> serializers,
            ObjectProvider<BaselineDataStore> baselineDataStore,
            ObjectProvider<CentralAuditFacade> auditFacade,
            ObjectProvider<SealedEvidencePackageIntegrity> integrity,
            ObjectProvider<PromptVersionCatalog> promptVersionCatalog,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        ObjectMapper tolerant = objectMapper.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        Supplier<SealedDecisionReplayService> service = () -> {
            SecurityDecisionStandardPromptTemplate template = templates.getIfAvailable();
            PipelineOrchestrator pipeline = pipelines.getIfAvailable();
            BaselineLearningService baselines = baselineLearning.getIfAvailable();
            if (template == null || pipeline == null || baselines == null) {
                return null;
            }
            SecurityZeroTrustProperties zeroTrust = zeroTrustProperties.getIfAvailable(SecurityZeroTrustProperties::new);
            return new SealedDecisionReplayService(template, pipeline, baselines,
                    tieredProperties.getIfAvailable(TieredStrategyProperties::new),
                    structuredOutput.getIfAvailable(StructuredOutputCapabilityRegistry::defaultRegistry),
                    modelSelection::getIfAvailable, zeroTrust.getMinimumAction().toRules(),
                    zeroTrust.getMinimumAction().getMode().name(),
                    serializers.getIfAvailable(() -> new CanonicalSecurityContextSerializer(tolerant)), tolerant);
        };
        // Plan 3.9: a replay names a version of the database (v2.0), drawn with its parts.
        return new SealedDecisionReplays(sealedEvidencePackageRepository, service, baselineDataStore.getIfAvailable(),
                auditFacade.getIfAvailable(), objectMapper, integrity.getIfAvailable(SealedEvidencePackageIntegrity::new),
                () -> promptVersionCatalog.getIfAvailable(PromptVersionCatalog::none));
    }

    @Bean(name = "contexaSealedDecisionReplayApiController")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SealedDecisionReplays.class)
    public SealedDecisionReplayApiController sealedDecisionReplayApiController(SealedDecisionReplays contexaSealedDecisionReplays) {
        return new SealedDecisionReplayApiController(contexaSealedDecisionReplays);
    }
}
