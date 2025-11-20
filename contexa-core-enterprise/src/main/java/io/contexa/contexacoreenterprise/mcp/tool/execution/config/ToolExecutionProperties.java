package io.contexa.contexacoreenterprise.mcp.tool.execution.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Tool Execution Properties
 * 
 * 도구 실행 전략과 관련된 설정 속성들입니다.
 * application.yml에서 tool.execution 아래의 속성들을 관리합니다.
 */
@Data
@ConfigurationProperties(prefix = "tool.execution")
public class ToolExecutionProperties {
    
    /**
     * 전역 설정
     */
    private GlobalConfig global = new GlobalConfig();
    
    /**
     * 전략별 설정
     */
    private StrategyConfig strategy = new StrategyConfig();
    
    /**
     * 캐시 설정
     */
    private CacheConfig cache = new CacheConfig();
    
    /**
     * 보안 설정
     */
    private SecurityConfig security = new SecurityConfig();
    
    /**
     * 타임아웃 설정
     */
    private TimeoutConfig timeout = new TimeoutConfig();
    
    /**
     * 전역 설정
     */
    @Data
    public static class GlobalConfig {
        /**
         * 전략 패턴 활성화 여부
         */
        private boolean enabled = true;
        
        /**
         * 최대 동시 실행 수
         */
        private int maxConcurrentExecutions = 10;
        
        /**
         * 기본 실행 타임아웃
         */
        private Duration defaultTimeout = Duration.ofSeconds(30);
        
        /**
         * 감사 로깅 활성화
         */
        private boolean auditLoggingEnabled = true;
        
        /**
         * 메트릭 수집 활성화
         */
        private boolean metricsEnabled = true;
    }
    
    /**
     * 전략별 설정
     */
    @Data
    public static class StrategyConfig {
        /**
         * 캐시 전략 설정
         */
        private CacheStrategyConfig cache = new CacheStrategyConfig();
        
        /**
         * 보안 전략 설정
         */
        private SecureStrategyConfig secure = new SecureStrategyConfig();
        
        /**
         * MCP 전략 설정
         */
        private McpStrategyConfig mcp = new McpStrategyConfig();
        
        /**
         * 로컬 전략 설정
         */
        private LocalStrategyConfig local = new LocalStrategyConfig();
    }
    
    /**
     * 캐시 전략 설정
     */
    @Data
    public static class CacheStrategyConfig {
        private boolean enabled = true;
        private int priority = 10;
        private Duration defaultTtl = Duration.ofMinutes(5);
        private long maxCacheSize = 1000;
        private boolean useWeakReferences = false;
    }
    
    /**
     * 보안 전략 설정
     */
    @Data
    public static class SecureStrategyConfig {
        private boolean enabled = true;
        private int priority = 20;
        private boolean strictMode = false;
        private boolean isolationEnabled = true;
        private Duration isolationTimeout = Duration.ofSeconds(30);
        private Map<String, String> highRiskTools = new HashMap<>();
    }
    
    /**
     * MCP 전략 설정
     */
    @Data
    public static class McpStrategyConfig {
        private boolean enabled = true;
        private int priority = 50;
        private Duration connectionTimeout = Duration.ofSeconds(5);
        private Duration requestTimeout = Duration.ofSeconds(30);
        private int maxRetries = 3;
        private Duration retryDelay = Duration.ofMillis(500);
    }
    
    /**
     * 로컬 전략 설정
     */
    @Data
    public static class LocalStrategyConfig {
        private boolean enabled = true;
        private int priority = 1000;
        private boolean sandboxEnabled = false;
        private Duration executionTimeout = Duration.ofSeconds(60);
    }
    
    /**
     * 캐시 설정
     */
    @Data
    public static class CacheConfig {
        /**
         * 캐시 타입 (memory, redis, hazelcast)
         */
        private String type = "memory";
        
        /**
         * 최대 캐시 크기
         */
        private long maxSize = 10000;
        
        /**
         * 기본 TTL
         */
        private Duration defaultTtl = Duration.ofMinutes(10);
        
        /**
         * 캐시 통계 활성화
         */
        private boolean statisticsEnabled = true;
        
        /**
         * 도구별 TTL 설정
         */
        private Map<String, Duration> toolTtls = new HashMap<>();
    }
    
    /**
     * 보안 설정
     */
    @Data
    public static class SecurityConfig {
        /**
         * 입력 검증 활성화
         */
        private boolean inputValidationEnabled = true;
        
        /**
         * 출력 정제 활성화
         */
        private boolean outputSanitizationEnabled = true;
        
        /**
         * 권한 확인 활성화
         */
        private boolean authorizationEnabled = true;
        
        /**
         * 승인 필요 도구 목록
         */
        private Map<String, ApprovalConfig> approvalRequired = new HashMap<>();
        
        /**
         * 차단된 도구 목록
         */
        private Map<String, String> blockedTools = new HashMap<>();
        
        /**
         * 프로덕션 모드
         */
        private boolean productionMode = false;
    }
    
    /**
     * 승인 설정
     */
    @Data
    public static class ApprovalConfig {
        private String riskLevel = "MEDIUM";
        private Duration timeout = Duration.ofMinutes(5);
        private boolean requireMultipleApprovers = false;
        private int minApprovers = 1;
    }
    
    /**
     * 타임아웃 설정
     */
    @Data
    public static class TimeoutConfig {
        /**
         * 도구별 타임아웃 설정
         */
        private Map<String, Duration> toolTimeouts = new HashMap<>();
        
        /**
         * 전략별 타임아웃 설정
         */
        private Map<String, Duration> strategyTimeouts = new HashMap<>();
        
        /**
         * 기본 타임아웃
         */
        private Duration defaultTimeout = Duration.ofSeconds(30);
        
        /**
         * 최대 타임아웃
         */
        private Duration maxTimeout = Duration.ofMinutes(5);
        
        /**
         * 승인 타임아웃
         */
        private Duration approvalTimeout = Duration.ofMinutes(5);
    }
    
    /**
     * 기본 설정값 초기화
     */
    public ToolExecutionProperties() {
        // 기본 도구별 TTL 설정
        this.cache.toolTtls.put("static_*", Duration.ofHours(1));
        this.cache.toolTtls.put("config_*", Duration.ofHours(1));
        this.cache.toolTtls.put("scan_*", Duration.ofMinutes(10));
        this.cache.toolTtls.put("analysis_*", Duration.ofMinutes(10));
        
        // 기본 고위험 도구 설정
        this.strategy.secure.highRiskTools.put("delete_*", "CRITICAL");
        this.strategy.secure.highRiskTools.put("kill_*", "CRITICAL");
        this.strategy.secure.highRiskTools.put("terminate_*", "CRITICAL");
        this.strategy.secure.highRiskTools.put("execute_*", "HIGH");
        this.strategy.secure.highRiskTools.put("isolate_*", "HIGH");
        
        // 기본 도구별 타임아웃 설정
        this.timeout.toolTimeouts.put("scan_*", Duration.ofMinutes(2));
        this.timeout.toolTimeouts.put("analysis_*", Duration.ofMinutes(2));
        this.timeout.toolTimeouts.put("execute_*", Duration.ofSeconds(30));
        
        // 기본 전략별 타임아웃 설정
        this.timeout.strategyTimeouts.put("CACHED_EXECUTION", Duration.ofSeconds(5));
        this.timeout.strategyTimeouts.put("SECURE_EXECUTION", Duration.ofSeconds(30));
        this.timeout.strategyTimeouts.put("MCP_EXECUTION", Duration.ofSeconds(60));
        this.timeout.strategyTimeouts.put("LOCAL_EXECUTION", Duration.ofSeconds(60));
    }
}