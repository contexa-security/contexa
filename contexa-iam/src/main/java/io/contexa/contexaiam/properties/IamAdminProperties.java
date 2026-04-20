package io.contexa.contexaiam.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.iam.admin")
public class IamAdminProperties {

    private String restDocsPath = "/docs/index.html";

    @NestedConfigurationProperty
    private ConditionTemplates conditionTemplates = new ConditionTemplates();

    @Data
    public static class ConditionTemplates {

        // Opt-in flag. When false, the automatic condition template generation path
        // triggered on application startup is skipped. Manual admin endpoints remain
        // unaffected.
        private boolean enabled = false;
    }
}
