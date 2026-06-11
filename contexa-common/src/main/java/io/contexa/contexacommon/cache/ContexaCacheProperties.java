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
package io.contexa.contexacommon.cache;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Data
@ConfigurationProperties(prefix = "contexa.cache")
public class ContexaCacheProperties {

    
    public enum CacheType {
        
        LOCAL,

        
        REDIS,

        
        HYBRID
    }

    
    private CacheType type = CacheType.REDIS;

    
    private LocalConfig local = new LocalConfig();

    
    private RedisConfig redis = new RedisConfig();

    
    private PubSubConfig pubsub = new PubSubConfig();

    
    private DomainConfig domains = new DomainConfig();

    
    @Data
    public static class LocalConfig {
        
        private int maxSize = 1000;

        
        private int defaultTtlSeconds = 60;
    }

    
    @Data
    public static class RedisConfig {
        
        private int defaultTtlSeconds = 300;

        
        private String keyPrefix = "contexa:cache:";
    }

    
    @Data
    public static class PubSubConfig {
        
        private boolean enabled = true;

        
        private String channel = "contexa:cache:invalidation";
    }

    
    @Data
    public static class DomainConfig {
        
        private TtlConfig users = new TtlConfig(3600, 3600);

        
        private TtlConfig roles = new TtlConfig(14400, 14400);

        
        private TtlConfig permissions = new TtlConfig(28800, 28800);

        
        private TtlConfig groups = new TtlConfig(14400, 14400);

        
        private TtlConfig policies = new TtlConfig(30, 300);

        
        private TtlConfig soar = new TtlConfig(900, 900);

        
        private TtlConfig hcad = new TtlConfig(86400, 86400);
    }

    
    @Data
    public static class TtlConfig {
        
        private int localTtlSeconds;

        
        private int redisTtlSeconds;

        public TtlConfig() {
            
        }

        public TtlConfig(int localTtlSeconds, int redisTtlSeconds) {
            this.localTtlSeconds = localTtlSeconds;
            this.redisTtlSeconds = redisTtlSeconds;
        }
    }
}
