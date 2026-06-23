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
package io.contexa.autoconfigure.core.hcad;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjectionFactory;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.hcad.service.GeoIpService;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceCache;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceCacheFactory;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceWarmupService;
import io.contexa.contexacore.hcad.semantic.JdbcHcadSemanticEvidenceWarmupService;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.hcad.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.hcad.store.InMemoryHCADDataStore;
import io.contexa.contexacore.hcad.store.RedisBaselineDataStore;
import io.contexa.contexacore.hcad.store.RedisHCADDataStore;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEligibilityGate;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceCheckService;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEventTriggerService;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerOrchestrator;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.hcad.trigger.store.InMemoryAnalysisTriggerStateRepository;
import io.contexa.contexacore.hcad.trigger.store.RedisAnalysisTriggerStateRepository;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowRepository;
import io.contexa.contexacore.hcad.trigger.window.InMemoryHcadObservationWindowRepository;
import io.contexa.contexacore.hcad.trigger.window.RedisHcadObservationWindowRepository;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcOperations;

@AutoConfiguration
@AutoConfigureAfter(value = CoreInfrastructureAutoConfiguration.class, name = {
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
@ConditionalOnProperty(prefix = "contexa.hcad", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, HcadProperties.class, TieredStrategyProperties.class })
public class CoreHCADAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.hcad.geoip", name = "enabled", havingValue = "true")
    public GeoIpService geoIpService(HcadProperties hcadProperties) {
        return new GeoIpService(hcadProperties.getGeoip().getDbPath());
    }

    @Bean
    @ConditionalOnMissingBean
    public BaselineLearningService baselineLearningService(
            BaselineDataStore baselineDataStore,
            HcadProperties hcadProperties) {
        return new BaselineLearningService(baselineDataStore, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HcadPreProtectablePromotionScorer hcadPreProtectablePromotionScorer(HcadProperties hcadProperties) {
        return new HcadPreProtectablePromotionScorer(hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HcadSemanticEvidenceCache hcadSemanticEvidenceCache(
            HcadProperties hcadProperties,
            ObjectMapper objectMapper,
            ObjectProvider<StringRedisTemplate> stringRedisTemplateProvider,
            Environment environment) {
        return HcadSemanticEvidenceCacheFactory.create(
                environment.getProperty("contexa.infrastructure.mode", "local"),
                hcadProperties,
                stringRedisTemplateProvider.getIfAvailable(),
                objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public HcadSemanticEvidenceWarmupService hcadSemanticEvidenceWarmupService(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            HcadProperties hcadProperties,
            ObjectProvider<TaskExecutor> taskExecutorProvider) {
        TaskExecutor taskExecutor = taskExecutorProvider.getIfAvailable();
        return new JdbcHcadSemanticEvidenceWarmupService(
                jdbcOperationsProvider::getIfAvailable,
                hcadProperties,
                taskExecutor == null ? null : taskExecutor::execute);
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustedHcadContextProjectionFactory trustedHcadContextProjectionFactory(
            HCADDataStore hcadDataStore,
            SecurityContextDataStore securityContextDataStore,
            BaselineDataStore baselineDataStore,
            HcadProperties hcadProperties) {
        return new TrustedHcadContextProjectionFactory(
                hcadDataStore,
                securityContextDataStore,
                baselineDataStore,
                hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.hcad.pre-trigger", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PendingAnomalyEligibilityGate pendingAnomalyEligibilityGate(
            ZeroTrustActionRepository actionRepository,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        return new PendingAnomalyEligibilityGate(actionRepository, analysisTriggerStateRepository, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyEligibilityGate.class)
    public PendingAnomalyEvidenceCheckService pendingAnomalyEvidenceCheckService() {
        return new PendingAnomalyEvidenceCheckService();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyEvidenceCheckService.class)
    public PendingAnomalyEventTriggerService pendingAnomalyEventTriggerService(
            ObjectProvider<ZeroTrustEventPublisher> zeroTrustEventPublisherProvider,
            HcadProperties hcadProperties) {
        return new PendingAnomalyEventTriggerService(zeroTrustEventPublisherProvider::getIfAvailable, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HcadEvaluationWriter hcadEvaluationWriter(
            ObjectProvider<HcadDetectionEvaluationRepository> hcadDetectionEvaluationRepositoryProvider,
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            ObjectMapper objectMapper) {
        return new HcadEvaluationWriter(
                hcadDetectionEvaluationRepositoryProvider::getIfAvailable,
                jdbcOperationsProvider::getIfAvailable,
                objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            ObjectMapper objectMapper) {
        return new AiSecurityDecisionObservationWriter(jdbcOperationsProvider::getIfAvailable, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyEvidenceCheckService.class)
    public PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate pendingAnomalyEligibilityGate,
            PendingAnomalyEvidenceCheckService pendingAnomalyEvidenceCheckService,
            ObjectProvider<PendingAnomalyEventTriggerService> pendingAnomalyEventTriggerServiceProvider,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties,
            ObjectProvider<HcadEvaluationWriter> hcadEvaluationWriterProvider) {
        return new PendingAnomalyTriggerOrchestrator(
                pendingAnomalyEligibilityGate,
                pendingAnomalyEvidenceCheckService,
                pendingAnomalyEventTriggerServiceProvider.getIfAvailable(),
                analysisTriggerStateRepository,
                hcadProperties,
                hcadEvaluationWriterProvider.getIfAvailable());
    }

    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(name = "generalRedisTemplate")
    static class DistributedHCADConfig {

        @Bean
        @ConditionalOnMissingBean(HCADDataStore.class)
        public RedisHCADDataStore hcadDataStore(RedisTemplate<String, Object> redisTemplate) {
            return new RedisHCADDataStore(redisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(BaselineDataStore.class)
        public RedisBaselineDataStore baselineDataStore(
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
            return new RedisBaselineDataStore(redisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(AnalysisTriggerStateRepository.class)
        public RedisAnalysisTriggerStateRepository analysisTriggerStateRepository(StringRedisTemplate stringRedisTemplate) {
            return new RedisAnalysisTriggerStateRepository(stringRedisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(HcadObservationWindowRepository.class)
        public RedisHcadObservationWindowRepository hcadObservationWindowRepository(StringRedisTemplate stringRedisTemplate) {
            return new RedisHcadObservationWindowRepository(stringRedisTemplate);
        }
    }

    @Bean
    @ConditionalOnMissingBean(HCADDataStore.class)
    public InMemoryHCADDataStore hcadDataStore() {
        return new InMemoryHCADDataStore();
    }

    @Bean
    @ConditionalOnMissingBean(BaselineDataStore.class)
    public InMemoryBaselineDataStore baselineDataStore() {
        return new InMemoryBaselineDataStore();
    }

    @Bean
    @ConditionalOnMissingBean(AnalysisTriggerStateRepository.class)
    public InMemoryAnalysisTriggerStateRepository analysisTriggerStateRepository() {
        return new InMemoryAnalysisTriggerStateRepository();
    }

    @Bean
    @ConditionalOnMissingBean(HcadObservationWindowRepository.class)
    public InMemoryHcadObservationWindowRepository hcadObservationWindowRepository() {
        return new InMemoryHcadObservationWindowRepository();
    }
}
