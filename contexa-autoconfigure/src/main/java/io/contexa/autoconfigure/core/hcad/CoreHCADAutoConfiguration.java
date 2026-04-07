package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.hcad.service.GeoIpService;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.hcad.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.hcad.store.InMemoryHCADDataStore;
import io.contexa.contexacore.hcad.store.RedisBaselineDataStore;
import io.contexa.contexacore.hcad.store.RedisHCADDataStore;
import io.contexa.contexacore.hcad.trigger.AuthenticatedPendingAnomalyTriggerFilter;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEligibilityGate;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceCheckService;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEventTriggerService;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerOrchestrator;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.hcad.trigger.store.InMemoryAnalysisTriggerStateRepository;
import io.contexa.contexacore.hcad.trigger.store.RedisAnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

@AutoConfiguration
@ConditionalOnProperty(prefix = "hcad", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, HcadProperties.class })
public class CoreHCADAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public HCADContextExtractor hcadContextExtractor(
            HCADDataStore hcadDataStore,
            SecurityContextDataStore securityContextDataStore,
            HcadProperties hcadProperties,
            ObjectProvider<BlockMfaStateStore> blockMfaStateStoreProvider,
            ObjectProvider<BaselineLearningService> baselineLearningServiceProvider,
            ObjectProvider<GeoIpService> geoIpServiceProvider) {
        HCADContextExtractor extractor = new HCADContextExtractor(hcadDataStore, securityContextDataStore, hcadProperties);
        extractor.setBlockMfaStateStore(blockMfaStateStoreProvider.getIfAvailable());
        extractor.setBaselineLearningService(baselineLearningServiceProvider.getIfAvailable());
        extractor.setGeoIpService(geoIpServiceProvider.getIfAvailable());
        return extractor;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "hcad.geoip", name = "enabled", havingValue = "true")
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
    public HCADAnalysisService hcadAnalysisService(
            HCADContextExtractor hcadContextExtractor,
            HcadProperties hcadProperties,
            HCADDataStore hcadDataStore) {
        return new HCADAnalysisService(hcadContextExtractor, hcadProperties, hcadDataStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public HCADFilter hcadFilter(HCADAnalysisService hcadAnalysisService,
            HcadProperties hcadProperties) {
        return new HCADFilter(hcadAnalysisService, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public FilterRegistrationBean<HCADFilter> hcadFilterRegistrationBean(HCADFilter hcadFilter, HcadProperties hcadProperties) {
        FilterRegistrationBean<HCADFilter> filterRegistrationBean = new FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(hcadFilter);
        filterRegistrationBean.setEnabled(hcadProperties.isEnabled());
        filterRegistrationBean.setOrder(hcadProperties.getFilterOrder());
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({ZeroTrustActionRepository.class, ZeroTrustEventPublisher.class, AnalysisTriggerStateRepository.class})
    @ConditionalOnProperty(prefix = "hcad.pre-trigger", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PendingAnomalyEligibilityGate pendingAnomalyEligibilityGate(
            ZeroTrustActionRepository actionRepository,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        return new PendingAnomalyEligibilityGate(actionRepository, analysisTriggerStateRepository, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyEligibilityGate.class)
    public PendingAnomalyEvidenceCheckService pendingAnomalyEvidenceCheckService(HcadProperties hcadProperties) {
        return new PendingAnomalyEvidenceCheckService(hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyEvidenceCheckService.class)
    public PendingAnomalyEventTriggerService pendingAnomalyEventTriggerService(ZeroTrustEventPublisher zeroTrustEventPublisher) {
        return new PendingAnomalyEventTriggerService(zeroTrustEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyEventTriggerService.class)
    public PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate pendingAnomalyEligibilityGate,
            PendingAnomalyEvidenceCheckService pendingAnomalyEvidenceCheckService,
            PendingAnomalyEventTriggerService pendingAnomalyEventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        return new PendingAnomalyTriggerOrchestrator(
                pendingAnomalyEligibilityGate,
                pendingAnomalyEvidenceCheckService,
                pendingAnomalyEventTriggerService,
                analysisTriggerStateRepository,
                hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PendingAnomalyTriggerOrchestrator.class)
    public AuthenticatedPendingAnomalyTriggerFilter authenticatedPendingAnomalyTriggerFilter(
            PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator,
            HcadProperties hcadProperties) {
        return new AuthenticatedPendingAnomalyTriggerFilter(pendingAnomalyTriggerOrchestrator, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthenticatedPendingAnomalyTriggerFilter.class)
    public FilterRegistrationBean<AuthenticatedPendingAnomalyTriggerFilter> authenticatedPendingAnomalyTriggerFilterRegistrationBean(
            AuthenticatedPendingAnomalyTriggerFilter authenticatedPendingAnomalyTriggerFilter,
            HcadProperties hcadProperties) {
        FilterRegistrationBean<AuthenticatedPendingAnomalyTriggerFilter> filterRegistrationBean = new FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(authenticatedPendingAnomalyTriggerFilter);
        filterRegistrationBean.setEnabled(hcadProperties.isEnabled() && hcadProperties.getPreTrigger().isEnabled());
        filterRegistrationBean.setOrder(hcadProperties.getFilterOrder() + 1);
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }

    @Configuration
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
    }

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    static class StandaloneHCADConfig {

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
    }
}
