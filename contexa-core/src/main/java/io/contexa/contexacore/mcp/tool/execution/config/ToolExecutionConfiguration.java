package io.contexa.contexacore.mcp.tool.execution.config;

import io.contexa.contexacore.mcp.cache.ToolResultCache;
import io.contexa.contexacore.autonomous.authorization.ToolAuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;


/**
 * Tool Execution Configuration
 * 
 * 도구 실행 관련 보안 및 캐싱 컴포넌트를 위한 Spring Configuration입니다.
 */
@Slf4j
@Configuration
@EnableConfigurationProperties(ToolExecutionProperties.class)
public class ToolExecutionConfiguration {
    
    
    
    
    /**
     * Tool Result Cache Bean
     * 
     * 도구 실행 결과를 캐싱하기 위한 캐시입니다.
     */
    @Bean
    @ConditionalOnMissingBean(ToolResultCache.class)
    public ToolResultCache toolResultCache(RedisTemplate<String, Object> redisTemplate) {
        log.info("Tool Result Cache 구성");
        return new ToolResultCache(redisTemplate);
    }
    
    /**
     * Tool Authorization Service Bean
     * 
     * 도구 실행 권한을 확인하는 서비스입니다.
     */
    @Bean
    @ConditionalOnMissingBean(ToolAuthorizationService.class)
    public ToolAuthorizationService toolAuthorizationService() {
        log.info("Tool Authorization Service 구성");
        return new ToolAuthorizationService();
    }

    /**
     * Configuration 초기화 완료 로깅
     */
    @Bean
    public ToolExecutionConfigurationLogger configurationLogger() {
        return new ToolExecutionConfigurationLogger();
    }
    
    /**
     * Configuration 로거
     */
    public static class ToolExecutionConfigurationLogger {
        public ToolExecutionConfigurationLogger() {
            log.info("════════════════════════════════════════════════════");
            log.info("Tool Execution Configuration 초기화 완료");
            log.info("MCP 통합 도구 실행 시스템 활성화");
            log.info("보안 검증 및 승인 메커니즘 통합 완료");
            log.info("════════════════════════════════════════════════════");
        }
    }
}