package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.HcadProperties;



import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;


@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.hcad",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)

@EnableConfigurationProperties({ContexaProperties.class, HcadProperties.class})
public class CoreHCADAutoConfiguration {

    public CoreHCADAutoConfiguration() {
        
    }

    

    
    
    

    
    @Bean
    @ConditionalOnMissingBean
    public HCADContextExtractor hcadContextExtractor(
            RedisTemplate<String, Object> redisTemplate) {
        return new HCADContextExtractor(redisTemplate);
    }

    
    

    
    @Bean
    @ConditionalOnMissingBean
    public BaselineLearningService baselineLearningService(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        return new BaselineLearningService(redisTemplate);
    }

    

    
    
    

    

    
    @Bean
    @ConditionalOnMissingBean
    public HCADAnalysisService hcadAnalysisService(
            HCADContextExtractor hcadContextExtractor) {
        return new HCADAnalysisService(hcadContextExtractor);
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public HCADFilter hcadFilter(HCADAnalysisService hcadAnalysisService) {
        return new HCADFilter(hcadAnalysisService);
    }
}
