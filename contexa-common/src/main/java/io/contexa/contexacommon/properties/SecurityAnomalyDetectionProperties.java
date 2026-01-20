package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;


@Data
@ConfigurationProperties(prefix = "security.anomaly-detection")
public class SecurityAnomalyDetectionProperties {

    
    private boolean enabled = false;

    
    private boolean blockOnAnomaly = true;

    
    private NotificationProperties notification = new NotificationProperties();

    @Data
    public static class NotificationProperties {
        
        private boolean enabled = false;

        
        private List<String> channels = Collections.emptyList();
    }
}
