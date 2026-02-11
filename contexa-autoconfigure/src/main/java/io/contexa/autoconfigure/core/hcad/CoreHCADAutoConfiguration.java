package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.HcadProperties;

import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.hcad", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, HcadProperties.class })
public class CoreHCADAutoConfiguration {

    public CoreHCADAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public HCADContextExtractor hcadContextExtractor(
            RedisTemplate<String, Object> redisTemplate,
            HcadProperties hcadProperties) {
        return new HCADContextExtractor(redisTemplate, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public BaselineLearningService baselineLearningService(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            HcadProperties hcadProperties) {
        return new BaselineLearningService(redisTemplate, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HCADAnalysisService hcadAnalysisService(
            HCADContextExtractor hcadContextExtractor,
            HcadProperties hcadProperties) {
        return new HCADAnalysisService(hcadContextExtractor, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HCADFilter hcadFilter(HCADAnalysisService hcadAnalysisService,
            HcadProperties hcadProperties) {
        return new HCADFilter(hcadAnalysisService, hcadProperties);
    }

    @Bean
    @ConditionalOnBean(HCADFilter.class)
    public FilterRegistrationBean hcadFilterRegistrationBean(HCADFilter hcadFilter){
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(hcadFilter);
        filterRegistrationBean.setEnabled(false);
        return filterRegistrationBean;
    }
}
