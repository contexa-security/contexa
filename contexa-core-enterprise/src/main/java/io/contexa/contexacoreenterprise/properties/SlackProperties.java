package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "slack")
public class SlackProperties {
    @NestedConfigurationProperty
    private WebhookSettings webhook = new WebhookSettings();
    @NestedConfigurationProperty
    private ApiSettings api = new ApiSettings();
    @NestedConfigurationProperty
    private ChannelSettings channel = new ChannelSettings();
    private String username = "contexa Bot";
    @NestedConfigurationProperty
    private IconSettings icon = new IconSettings();
    @NestedConfigurationProperty
    private RetrySettings retry = new RetrySettings();
    @NestedConfigurationProperty
    private RateLimitSettings rateLimit = new RateLimitSettings();
    private boolean enabled = false;

    @Data
    public static class WebhookSettings {
        private String url = "";
    }
    @Data
    public static class ApiSettings {
        private String token = "";
    }
    @Data
    public static class ChannelSettings {
        private String defaultChannel = "#security-alerts";
        private String urgent = "#security-urgent";
        private String approval = "#security-approvals";
    }
    @Data
    public static class IconSettings {
        private String emoji = ":shield:";
    }
    @Data
    public static class RetrySettings {
        private int maxAttempts = 3;
        private int delaySeconds = 2;
    }
    @Data
    public static class RateLimitSettings {
        private int messagesPerMinute = 20;
    }
}
