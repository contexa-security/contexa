package io.contexa.contexacore.std.rag.properties;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.ai.vectorstore.properties.CommonVectorStoreProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;


@ConfigurationProperties(prefix = "spring.ai.vectorstore.pgvector")
@Validated
@Data
@EqualsAndHashCode(callSuper = true)
public class PgVectorStoreProperties extends CommonVectorStoreProperties {

    
    @NotNull
    private IndexType indexType = IndexType.HNSW;

    
    @NotNull
    private DistanceType distanceType = DistanceType.COSINE_DISTANCE;

    
    @Min(128)
    @Max(3072)
    private int dimensions = 1024;

    
    @Min(1)
    @Max(1000)
    private int batchSize = 100;

    
    @Min(1)
    @Max(32)
    private int parallelThreads = 4;

    
    @Min(1)
    @Max(1000)
    private int topK = 100;

    
    @DecimalMin("0.0")
    @DecimalMax("1.0")
    private double similarityThreshold = 0.5;

    
    private HnswConfig hnsw = new HnswConfig();

    
    private IvfflatConfig ivfflat = new IvfflatConfig();

    
    private DocumentConfig document = new DocumentConfig();

    
    @Data
    public static class HnswConfig {
        
        @Min(4)
        @Max(64)
        private int m = 16;

        
        @Min(10)
        @Max(500)
        private int efConstruction = 64;

        
        @Min(10)
        @Max(500)
        private int efSearch = 100;
    }

    
    @Data
    public static class IvfflatConfig {
        
        @Min(1)
        @Max(10000)
        private int lists = 100;

        
        @Min(1)
        @Max(1000)
        private int probes = 10;
    }

    
    @Data
    public static class DocumentConfig {
        
        @Min(100)
        @Max(10000)
        private int chunkSize = 1000;

        
        @Min(0)
        @Max(1000)
        private int chunkOverlap = 200;

        
        private boolean enrichMetadata = true;

        
        private boolean extractKeywords = true;

        
        private boolean generateSummary = false;
    }

    
    public enum IndexType {
        HNSW,
        IVFFLAT
    }

    
    public enum DistanceType {
        COSINE_DISTANCE,
        EUCLIDEAN_DISTANCE,
        NEGATIVE_INNER_PRODUCT
    }
}
