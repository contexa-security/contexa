package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Data
@ConfigurationProperties(prefix = "contexa")
public class ContexaProperties {

    
    private boolean enabled = true;

    
    private Hcad hcad = new Hcad();

    
    private Llm llm = new Llm();

    
    private Rag rag = new Rag();

    
    private Autonomous autonomous = new Autonomous();

    
    private Simulation simulation = new Simulation();

    
    private Feedback feedback = new Feedback();

    
    private Infrastructure infrastructure = new Infrastructure();

    
    
    

    
    @Data
    public static class Hcad {
        
        private boolean enabled = true;


        private Similarity similarity = new Similarity();

        
        private Baseline baseline = new Baseline();

        @Data
        public static class Similarity {
            
            private double hotPathThreshold = 0.7;

            
            private double minimalThreshold = 0.8;

            
            private double lowThreshold = 0.6;

            
            private double mediumThreshold = 0.4;

            
            private double highThreshold = 0.2;
        }

        @Data
        public static class Baseline {
            
            private int minSamples = 10;

            
            private int cacheTtl = 3600;

            
            private boolean autoLearning = true;
        }
    }

    
    @Data
    public static class Llm {
        
        private boolean enabled = true;

        
        private boolean tieredEnabled = true;

        
        private boolean advisorEnabled = true;

        
        private boolean pipelineEnabled = true;
    }

    
    @Data
    public static class Rag {
        
        private boolean enabled = true;

        
        private VectorStore vectorStore = new VectorStore();

        @Data
        public static class VectorStore {
            
            private String type = "pgvector";

            
            private int defaultTopK = 5;

            
            private double defaultSimilarityThreshold = 0.7;
        }
    }

    
    @Data
    public static class Autonomous {
        
        private boolean enabled = true;

        
        private String strategyMode = "dynamic";

        
        private long eventTimeout = 30000;
    }

    
    @Data
    public static class Simulation {
        
        private boolean enabled = false;

        
        private SimulationData data = new SimulationData();

        @lombok.Data
        public static class SimulationData {
            
            private boolean enabled = false;

            
            private boolean clearExisting = false;
        }
    }

    
    @Data
    public static class Feedback {
        
        private boolean enabled = true;

        
        private long collectionInterval = 60000;
    }

    
    public enum InfrastructureMode {
        STANDALONE,
        DISTRIBUTED
    }

    @Data
    public static class Infrastructure {

        private InfrastructureMode mode = InfrastructureMode.STANDALONE;

        private Redis redis = new Redis();


        private Kafka kafka = new Kafka();


        private Observability observability = new Observability();

        @Data
        public static class Redis {
            
            private boolean enabled = true;

            
            private boolean redissonEnabled = false;
        }

        @Data
        public static class Kafka {
            
            private boolean enabled = true;
        }

        @Data
        public static class Observability {
            
            private boolean enabled = true;

            
            private boolean openTelemetryEnabled = true;
        }
    }
}
