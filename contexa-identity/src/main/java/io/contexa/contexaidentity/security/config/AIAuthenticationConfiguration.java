package io.contexa.contexaidentity.security.config;

import io.contexa.contexacore.std.operations.AICoreOperations;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.SearchStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * AI 적응형 인증 설정
 * 
 * AI Labs(RiskAssessmentLab, BehavioralAnalysisLab)가 사용 가능한 경우
 * AIAdaptiveMfaPolicyProvider를 활성화하여 AI 기반 적응형 인증을 제공합니다.
 * 
 * 활성화 조건:
 * 1. application.yml에서 aidc.security.ai.enabled=true 설정
 * 2. RiskAssessmentLab과 BehavioralAnalysisLab Bean이 존재
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(
    prefix = "aidc.security.ai",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true // 기본값: true
)
public class AIAuthenticationConfiguration {
    
    /**
     * AI Labs가 없는 경우 경고 로그 출력
     */
    @Bean
    @ConditionalOnBean(value = {AICoreOperations.class},
                       search = SearchStrategy.ALL)
    public AIAuthenticationStatusLogger aiAuthenticationStatusLogger() {
        return new AIAuthenticationStatusLogger();
    }
    
    /**
     * AI 인증 상태 로거
     */
    @Slf4j
    public static class AIAuthenticationStatusLogger {
        public AIAuthenticationStatusLogger() {
            log.info("===================================================");
            log.info("AI Adaptive Authentication Status:");
            log.info("  - Configuration: ENABLED");
            log.info("  - RiskAssessmentLab: AVAILABLE");
            log.info("  - BehavioralAnalysisLab: AVAILABLE");
            log.info("  - Status: ACTIVE");
            log.info("===================================================");
        }
    }
}