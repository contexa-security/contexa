package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Contexa Advisor 설정
 */
@Data
@ConfigurationProperties(prefix = "contexa.advisor")
public class ContexaAdvisorProperties {

    /**
     * 체인 프로파일 (STANDARD, ENHANCED 등)
     */
    private String chainProfile = "STANDARD";

    /**
     * Security Advisor 설정
     */
    @NestedConfigurationProperty
    private SecurityAdvisorSettings security = new SecurityAdvisorSettings();

    /**
     * SOAR Advisor 설정
     */
    @NestedConfigurationProperty
    private SoarAdvisorSettings soar = new SoarAdvisorSettings();

    /**
     * Security Advisor 설정
     */
    @Data
    public static class SecurityAdvisorSettings {
        private boolean enabled = true;
        private int order = 50;
        private boolean requireAuthentication = false;
    }

    /**
     * SOAR Advisor 설정
     */
    @Data
    public static class SoarAdvisorSettings {
        @NestedConfigurationProperty
        private ApprovalSettings approval = new ApprovalSettings();

        @Data
        public static class ApprovalSettings {
            private boolean enabled = true;
            private int order = 100;
            private int timeout = 300;
        }
    }
}
