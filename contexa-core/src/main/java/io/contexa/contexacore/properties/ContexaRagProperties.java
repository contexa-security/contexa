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
    private Behavior behavior = new Behavior();

    @NestedConfigurationProperty
    private Risk risk = new Risk();

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
    public static class Behavior {
        private int lookbackDays = 30;
    }

    @Data
    public static class Risk {
        private double similarityThreshold = 0.8;
        private int topK = 50;
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
