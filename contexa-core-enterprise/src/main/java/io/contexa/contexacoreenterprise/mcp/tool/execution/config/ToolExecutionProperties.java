package io.contexa.contexacoreenterprise.mcp.tool.execution.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "tool.execution")
public class ToolExecutionProperties {

    private GlobalConfig global = new GlobalConfig();

    private StrategyConfig strategy = new StrategyConfig();

    private CacheConfig cache = new CacheConfig();

    private SecurityConfig security = new SecurityConfig();

    private TimeoutConfig timeout = new TimeoutConfig();

    @Data
    public static class GlobalConfig {
        
        private boolean enabled = true;

        private int maxConcurrentExecutions = 10;

        private Duration defaultTimeout = Duration.ofSeconds(30);

        private boolean auditLoggingEnabled = true;

        private boolean metricsEnabled = true;
    }

    @Data
    public static class StrategyConfig {
        
        private CacheStrategyConfig cache = new CacheStrategyConfig();

        private SecureStrategyConfig secure = new SecureStrategyConfig();

        private McpStrategyConfig mcp = new McpStrategyConfig();

        private LocalStrategyConfig local = new LocalStrategyConfig();
    }

    @Data
    public static class CacheStrategyConfig {
        private boolean enabled = true;
        private int priority = 10;
        private Duration defaultTtl = Duration.ofMinutes(5);
        private long maxCacheSize = 1000;
        private boolean useWeakReferences = false;
    }

    @Data
    public static class SecureStrategyConfig {
        private boolean enabled = true;
        private int priority = 20;
        private boolean strictMode = false;
        private boolean isolationEnabled = true;
        private Duration isolationTimeout = Duration.ofSeconds(30);
        private Map<String, String> highRiskTools = new HashMap<>();
    }

    @Data
    public static class McpStrategyConfig {
        private boolean enabled = true;
        private int priority = 50;
        private Duration connectionTimeout = Duration.ofSeconds(5);
        private Duration requestTimeout = Duration.ofSeconds(30);
        private int maxRetries = 3;
        private Duration retryDelay = Duration.ofMillis(500);
    }

    @Data
    public static class LocalStrategyConfig {
        private boolean enabled = true;
        private int priority = 1000;
        private boolean sandboxEnabled = false;
        private Duration executionTimeout = Duration.ofSeconds(60);
    }

    @Data
    public static class CacheConfig {
        
        private String type = "memory";

        private long maxSize = 10000;

        private Duration defaultTtl = Duration.ofMinutes(10);

        private boolean statisticsEnabled = true;

        private Map<String, Duration> toolTtls = new HashMap<>();
    }

    @Data
    public static class SecurityConfig {
        
        private boolean inputValidationEnabled = true;

        private boolean outputSanitizationEnabled = true;

        private boolean authorizationEnabled = true;

        private Map<String, ApprovalConfig> approvalRequired = new HashMap<>();

        private Map<String, String> blockedTools = new HashMap<>();

        private boolean productionMode = false;
    }

    @Data
    public static class ApprovalConfig {
        private String riskLevel = "MEDIUM";
        private Duration timeout = Duration.ofMinutes(5);
        private boolean requireMultipleApprovers = false;
        private int minApprovers = 1;
    }

    @Data
    public static class TimeoutConfig {
        
        private Map<String, Duration> toolTimeouts = new HashMap<>();

        private Map<String, Duration> strategyTimeouts = new HashMap<>();

        private Duration defaultTimeout = Duration.ofSeconds(30);

        private Duration maxTimeout = Duration.ofMinutes(5);

        private Duration approvalTimeout = Duration.ofMinutes(5);
    }

    public ToolExecutionProperties() {
        
        this.cache.toolTtls.put("static_*", Duration.ofHours(1));
        this.cache.toolTtls.put("config_*", Duration.ofHours(1));
        this.cache.toolTtls.put("scan_*", Duration.ofMinutes(10));
        this.cache.toolTtls.put("analysis_*", Duration.ofMinutes(10));

        this.strategy.secure.highRiskTools.put("delete_*", "CRITICAL");
        this.strategy.secure.highRiskTools.put("kill_*", "CRITICAL");
        this.strategy.secure.highRiskTools.put("terminate_*", "CRITICAL");
        this.strategy.secure.highRiskTools.put("execute_*", "HIGH");
        this.strategy.secure.highRiskTools.put("isolate_*", "HIGH");

        this.timeout.toolTimeouts.put("scan_*", Duration.ofMinutes(2));
        this.timeout.toolTimeouts.put("analysis_*", Duration.ofMinutes(2));
        this.timeout.toolTimeouts.put("execute_*", Duration.ofSeconds(30));

        this.timeout.strategyTimeouts.put("CACHED_EXECUTION", Duration.ofSeconds(5));
        this.timeout.strategyTimeouts.put("SECURE_EXECUTION", Duration.ofSeconds(30));
        this.timeout.strategyTimeouts.put("MCP_EXECUTION", Duration.ofSeconds(60));
        this.timeout.strategyTimeouts.put("LOCAL_EXECUTION", Duration.ofSeconds(60));
    }
}