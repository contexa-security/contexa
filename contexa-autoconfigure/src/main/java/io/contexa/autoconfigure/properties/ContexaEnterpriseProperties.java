package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Data
@ConfigurationProperties(prefix = "contexa.enterprise")
public class ContexaEnterpriseProperties {

    
    private boolean enabled = false;

    
    private Evolution evolution = new Evolution();

    
    private Intelligence intelligence = new Intelligence();

    
    private Mcp mcp = new Mcp();

    
    private Soar soar = new Soar();

    
    private Dashboard dashboard = new Dashboard();

    
    private Notification notification = new Notification();

    
    private Scheduler scheduler = new Scheduler();

    
    
    

    
    @Data
    public static class Evolution {
        
        private boolean enabled = true;

        
        private double threshold = 0.75;

        
        private int minSamples = 10;

        
        private int retentionDays = 90;
    }

    
    @Data
    public static class Intelligence {
        
        private boolean tuningEnabled = true;

        
        private boolean xaiReportingEnabled = true;
    }

    
    @Data
    public static class Mcp {
        
        private boolean enabled = true;

        
        private ToolExecution toolExecution = new ToolExecution();

        @Data
        public static class ToolExecution {
            
            private boolean enabled = true;

            
            private long timeout = 30000;

            
            private int retryCount = 3;
        }
    }

    
    @Data
    public static class Soar {
        
        private boolean enabled = true;

        
        private Approval approval = new Approval();

        @Data
        public static class Approval {
            
            private boolean enabled = true;

            
            private long timeout = 300000;

            
            private boolean autoApprove = false;
        }
    }

    
    @Data
    public static class Dashboard {
        
        private boolean enabled = true;

        
        private long metricsInterval = 60000;

        
        private boolean eventRecordingEnabled = true;
    }

    
    @Data
    public static class Notification {
        
        private boolean enabled = true;

        
        private boolean slackEnabled = false;

        
        private boolean smsEnabled = false;

        
        private boolean emailEnabled = true;
    }

    
    @Data
    public static class Scheduler {
        
        private boolean enabled = true;

        
        private boolean policyEvolutionEnabled = true;

        
        private boolean staticAnalysisEnabled = true;

        
        private boolean vectorLearningEnabled = true;
    }
}
