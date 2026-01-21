package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.advisor")
public class ContexaAdvisorProperties {

    private String chainProfile = "STANDARD";

    @NestedConfigurationProperty
    private SecurityAdvisorSettings security = new SecurityAdvisorSettings();

    @NestedConfigurationProperty
    private SoarAdvisorSettings soar = new SoarAdvisorSettings();

    @Data
    public static class SecurityAdvisorSettings {
        private boolean enabled = true;
        private int order = 50;
        private boolean requireAuthentication = false;
    }

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
