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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BR-S8: the pgvector settings Contexa never reads are marked as having no effect in the configuration metadata, while
 * every key still binds as it did (no behaviour change).
 */
class PgVectorStorePropertiesTest {

    private static final String PREFIX = "contexa.vectorstore.pgvector.";
    private static final List<String> WITHOUT_EFFECT = List.of("hnsw.m", "hnsw.ef-construction", "ivfflat.lists",
            "ivfflat.probes", "document.chunk-size", "document.chunk-overlap", "document.enrich-metadata",
            "document.extract-keywords", "document.generate-summary");

    @Test
    void everyKeyBindsAsBefore() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put(PREFIX + "index-type", "IVFFLAT");
        values.put(PREFIX + "distance-type", "EUCLIDEAN_DISTANCE");
        values.put(PREFIX + "hnsw.m", "32");
        values.put(PREFIX + "hnsw.ef-construction", "128");
        values.put(PREFIX + "hnsw.ef-search", "200");
        values.put(PREFIX + "ivfflat.lists", "50");
        values.put(PREFIX + "ivfflat.probes", "5");
        values.put(PREFIX + "document.chunk-size", "500");

        PgVectorStoreProperties bound = new Binder(new MapConfigurationPropertySource(values))
                .bind("contexa.vectorstore.pgvector", PgVectorStoreProperties.class).get();

        assertThat(bound.getIndexType()).isEqualTo(PgVectorStoreProperties.IndexType.IVFFLAT);
        assertThat(bound.getDistanceType()).isEqualTo(PgVectorStoreProperties.DistanceType.EUCLIDEAN_DISTANCE);
        assertThat(bound.getHnsw().getM()).isEqualTo(32);
        assertThat(bound.getHnsw().getEfConstruction()).isEqualTo(128);
        assertThat(bound.getHnsw().getEfSearch()).isEqualTo(200);
        assertThat(bound.getIvfflat().getLists()).isEqualTo(50);
        assertThat(bound.getIvfflat().getProbes()).isEqualTo(5);
        assertThat(bound.getDocument().getChunkSize()).isEqualTo(500);
    }

    @Test
    void theDefaultsAreAsBefore() {
        PgVectorStoreProperties defaults = new PgVectorStoreProperties();

        assertThat(defaults.getIndexType()).isEqualTo(PgVectorStoreProperties.IndexType.HNSW);
        assertThat(defaults.getDistanceType()).isEqualTo(PgVectorStoreProperties.DistanceType.COSINE_DISTANCE);
        assertThat(defaults.getDimensions()).isEqualTo(1024);
        assertThat(defaults.getHnsw().getM()).isEqualTo(16);
        assertThat(defaults.getHnsw().getEfConstruction()).isEqualTo(64);
        assertThat(defaults.getHnsw().getEfSearch()).isEqualTo(100);
        assertThat(defaults.getIvfflat().getLists()).isEqualTo(100);
        assertThat(defaults.getIvfflat().getProbes()).isEqualTo(10);
        assertThat(defaults.getDocument().getChunkSize()).isEqualTo(1000);
        assertThat(defaults.getDocument().getChunkOverlap()).isEqualTo(200);
    }

    @Test
    void theKeysWithoutEffectAreMarkedSoInTheMetadata() throws IOException {
        Map<String, JsonNode> properties = metadataProperties();

        for (String key : WITHOUT_EFFECT) {
            JsonNode property = properties.get(PREFIX + key);
            assertThat(property).as(PREFIX + key).isNotNull();
            assertThat(property.path("deprecated").asBoolean()).as(PREFIX + key + " deprecated").isTrue();
            assertThat(property.path("deprecation").path("reason").asText()).as(PREFIX + key + " reason")
                    .contains("no effect");
        }
        assertThat(properties.get(PREFIX + "hnsw.ef-search").path("deprecated").asBoolean())
                .as("ef-search is read by the search").isFalse();
        assertThat(properties.get(PREFIX + "index-type").path("deprecated").asBoolean()).isFalse();
    }

    private static Map<String, JsonNode> metadataProperties() throws IOException {
        Map<String, JsonNode> properties = new LinkedHashMap<>();
        ObjectMapper json = new ObjectMapper();
        Enumeration<URL> resources = PgVectorStorePropertiesTest.class.getClassLoader()
                .getResources("META-INF/spring-configuration-metadata.json");
        while (resources.hasMoreElements()) {
            try (InputStream in = resources.nextElement().openStream()) {
                for (JsonNode property : json.readTree(in).path("properties")) {
                    String name = property.path("name").asText();
                    if (name.startsWith(PREFIX)) {
                        properties.put(name, property);
                    }
                }
            }
        }
        return properties;
    }
}
