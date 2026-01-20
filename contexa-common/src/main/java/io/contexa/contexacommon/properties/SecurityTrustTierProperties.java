package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Data
@ConfigurationProperties(prefix = "security.trust-tier")
public class SecurityTrustTierProperties {

    
    private boolean enabled = false;

    
    private CacheProperties cache = new CacheProperties();

    
    private DefaultProperties defaults = new DefaultProperties();

    
    private ThresholdProperties thresholds = new ThresholdProperties();

    
    private FilterRules filterRules = new FilterRules();

    @Data
    public static class CacheProperties {
        
        private int ttlMinutes = 5;
    }

    @Data
    public static class DefaultProperties {
        
        private double trustScore = 0.3;
    }

    @Data
    public static class ThresholdProperties {
        
        private double tier1 = 0.8;

        
        private double tier2 = 0.6;

        
        private double tier3 = 0.4;

        
    }

    @Data
    public static class FilterRules {
        
        private java.util.List<String> tier2ExcludeKeywords = java.util.Arrays.asList(
                "ADMIN", "DELETE", "MODIFY_CRITICAL"
        );

        
        private java.util.List<String> tier3AllowKeywords = java.util.Arrays.asList(
                "READ", "VIEW", "LIST"
        );

        
        private java.util.List<String> tier4AllowAuthorities = java.util.Arrays.asList(
                "ROLE_MINIMAL", "PERMISSION_VIEW_PROFILE"
        );
    }
}
