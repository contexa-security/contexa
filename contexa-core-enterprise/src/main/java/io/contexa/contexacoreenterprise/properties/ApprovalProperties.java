package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "approval")
public class ApprovalProperties {
    private int timeout = 60;
    private AutoApprove autoApprove = new AutoApprove();

    @Data
    public static class AutoApprove {
        private boolean enabled = false;
    }
}
