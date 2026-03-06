package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.rag")
public class ContexaRagProperties {

    @NestedConfigurationProperty
    private Defaults defaults = new Defaults();

    @NestedConfigurationProperty
    private Lab lab = new Lab();

    @NestedConfigurationProperty
    private Etl etl = new Etl();

    @Data
    public static class Defaults {
        private double similarityThreshold = 0.7;
        private int topK = 10;
    }

    @Data
    public static class Lab {
        private int batchSize = 50;
        private boolean validationEnabled = true;
        private boolean enrichmentEnabled = true;
        private int topK = 100;
        private double similarityThreshold = 0.75;
    }

    @Data
    public static class Etl {
        private int batchSize = 100;
        private int chunkSize = 500;
        private int chunkOverlap = 50;
        private String vectorTableName = "vector_store";

        @NestedConfigurationProperty
        private Behavior behavior = new Behavior();

        @Data
        public static class Behavior {
            private int retentionDays = 90;
        }
    }
}
