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

import io.contexa.contexacommon.store.ApplicationNamespace;
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
        
        /** Z-16 (F2): as long as an entry lasts in the local cache by default, so both modes see a change as soon. */
        private int defaultTtlSeconds = 60;

        
        private String keyPrefix = "contexa:cache:";

        /** The prefix this application keeps its entries under: behind its name when it has one. */
        public String qualifiedKeyPrefix() {
            return ApplicationNamespace.key(keyPrefix);
        }
    }

    
    @Data
    public static class PubSubConfig {
        
        private boolean enabled = true;

        
        private String channel = "contexa:cache:invalidation";

        /** The channel this application publishes invalidations to and listens on: behind its name when it has one. */
        public String qualifiedChannel() {
            return ApplicationNamespace.key(channel);
        }
    }

    
    @Data
    public static class DomainConfig {
        
        private TtlConfig users = new TtlConfig(3600, 3600);

        
        private TtlConfig roles = new TtlConfig(14400, 14400);

        
        private TtlConfig permissions = new TtlConfig(28800, 28800);

        
        private TtlConfig groups = new TtlConfig(14400, 14400);

        
        /** Z-16 (F2): one TTL in either mode, the shorter, so an authorization policy changes as soon in both. */
        private TtlConfig policies = new TtlConfig(30, 30);

        
        private TtlConfig soar = new TtlConfig(900, 900);

        
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
