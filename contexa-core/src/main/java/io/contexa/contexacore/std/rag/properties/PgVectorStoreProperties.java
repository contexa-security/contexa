/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.rag.properties;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.DeprecatedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

/**
 * The pgvector settings of the Contexa vector service ({@code contexa.vectorstore.pgvector.*}).
 * <p>
 * The table, its index and its schema are Spring AI's {@code PgVectorStore}: a key set here under this prefix is also
 * given to Spring AI as {@code spring.ai.vectorstore.pgvector.*} (unless that key is set itself), so
 * {@code index-type}, {@code distance-type}, {@code dimensions} and {@code initialize-schema} reach the store through
 * Spring AI's auto-configuration. BR-S8, {@code initialize-schema}: Contexa's defaults set
 * {@code spring.ai.vectorstore.pgvector.initialize-schema=true}, against Spring AI's own default false, so that a first
 * start creates the extension, the table and its HNSW index, and the metadata index of the personal search is created
 * only then. A production database whose schema is managed by migrations should set it to false and create the
 * table, the vector index and the metadata index itself; with false, nothing is created or changed at start.
 * <p>
 * BR-S8: {@code hnsw.m}, {@code hnsw.ef-construction}, {@code ivfflat.*} and {@code document.*} are read by nothing
 * (Spring AI creates its index with its own parameters and has no such keys); they still bind and validate as before
 * and are marked deprecated, with no effect, in the configuration metadata. {@code hnsw.ef-search} is applied to every
 * similarity search.
 */
@ConfigurationProperties(prefix = "contexa.vectorstore.pgvector")
@Validated
@Data
public class PgVectorStoreProperties {

    /**
     * The index type; Contexa does not read it, a value set here is given to Spring AI as
     * spring.ai.vectorstore.pgvector.index-type.
     */
    @NotNull
    private IndexType indexType = IndexType.HNSW;

    /**
     * The distance type; Contexa does not read it, a value set here is given to Spring AI as
     * spring.ai.vectorstore.pgvector.distance-type.
     */
    @NotNull
    private DistanceType distanceType = DistanceType.COSINE_DISTANCE;

    @Min(128)
    @Max(3072)
    private int dimensions = 1024;

    @Min(1)
    @Max(1000)
    private int batchSize = 100;

    /**
     * Threads of the vector operation executor: searches, which wait on the embedding call before they read the
     * database, and stores share it (W2-15). Sized for the engine's concurrent analyses.
     */
    @Min(1)
    @Max(32)
    private int parallelThreads = 16;

    @Min(1)
    @Max(1000)
    private int topK = 100;

    @DecimalMin("0.0")
    @DecimalMax("1.0")
    private double similarityThreshold = 0.5;

    @Min(100)
    @Max(600000)
    private long searchTimeoutMs = 15000;

    @Min(100)
    @Max(600000)
    private long storeTimeoutMs = 15000;

    private HnswConfig hnsw = new HnswConfig();

    private IvfflatConfig ivfflat = new IvfflatConfig();

    private DocumentConfig document = new DocumentConfig();

    /** The reason the keys Contexa never reads give in the configuration metadata (BR-S8). */
    static final String NO_EFFECT = "Read by nothing, so it has no effect: Spring AI's PgVectorStore creates the index"
            + " with its own parameters.";

    @Data
    public static class HnswConfig {

        @Min(4)
        @Max(64)
        private int m = 16;

        @Min(10)
        @Max(500)
        private int efConstruction = 64;

        /** The hnsw.ef_search a similarity search is run with. */
        @Min(10)
        @Max(500)
        private int efSearch = 100;

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public int getM() {
            return m;
        }

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public int getEfConstruction() {
            return efConstruction;
        }
    }

    @Data
    public static class IvfflatConfig {

        @Min(1)
        @Max(10000)
        private int lists = 100;

        @Min(1)
        @Max(1000)
        private int probes = 10;

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public int getLists() {
            return lists;
        }

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public int getProbes() {
            return probes;
        }
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

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public int getChunkSize() {
            return chunkSize;
        }

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public int getChunkOverlap() {
            return chunkOverlap;
        }

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public boolean isEnrichMetadata() {
            return enrichMetadata;
        }

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public boolean isExtractKeywords() {
            return extractKeywords;
        }

        @DeprecatedConfigurationProperty(reason = NO_EFFECT)
        public boolean isGenerateSummary() {
            return generateSummary;
        }
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
