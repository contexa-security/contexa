package io.contexa.contexacore.soar.config;

import io.contexa.contexacore.soar.tool.exception.SoarToolExecutionExceptionProcessor;
import io.contexa.contexacore.mcp.tool.resolution.ChainedToolResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.tool.execution.ToolExecutionExceptionProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * SOAR Tool Configuration
 * 
 * Spring AI Tool 관련 Bean 설정을 중앙화합니다.
 * DefaultToolCallingManager를 Spring Bean으로 관리하여 DI 원칙을 준수합니다.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SoarToolConfiguration {
    
    
    /**
     * SOAR 전용 ToolCallingManager Bean
     * 
     * SOAR 도구 실행을 위한 커스터마이징된 ToolCallingManager입니다.
     * ToolCallbackResolver를 통해 도구를 동적으로 해결합니다.
     */
    @Bean(name = "soarToolCallingManager")
    public ToolCallingManager soarToolCallingManager(
            ChainedToolResolver toolResolver) {
        log.info("SOAR ToolCallingManager Bean 생성");
        
        // ChainedToolResolver를 통해 도구를 동적으로 해결
        return DefaultToolCallingManager.builder()
            .build();
    }
    
    /**
     * Tool 승인 정책 관리자
     * 
     * 도구별 승인 정책을 관리하는 Bean입니다.
     * 하드코딩된 로직 대신 정책 기반으로 승인 여부를 결정합니다.
     */
    @Bean
    public ToolApprovalPolicyManager toolApprovalPolicyManager() {
        log.info("Tool Approval Policy Manager Bean 생성");
        return new ToolApprovalPolicyManager();
    }
    
    /**
     * Tool 실행 메트릭 수집기
     * 
     * 도구 실행 관련 메트릭을 수집하는 Bean입니다.
     */
    @Bean
    public ToolExecutionMetrics toolExecutionMetrics() {
        log.info("Tool Execution Metrics Bean 생성");
        return new ToolExecutionMetrics();
    }
    
    /**
     * SOAR Tool 실행 예외 처리기
     * 
     * Spring AI의 ToolExecutionExceptionProcessor를 확장하여
     * 보안 도구 특화 예외 처리를 제공합니다.
     * 
     * @param throwOnError 예외 발생 시 던질지 여부 (기본값: false)
     * @return SOAR 특화 예외 처리기
     */
    @Bean
    @Primary
    public SoarToolExecutionExceptionProcessor toolExecutionExceptionProcessor(
            @Value("${spring.ai.tools.throw-exception-on-error:false}") boolean throwOnError) {
        log.info("SOAR Tool Execution Exception Processor Bean 생성 (throwOnError: {})", throwOnError);
        return new SoarToolExecutionExceptionProcessor(throwOnError);
    }
}