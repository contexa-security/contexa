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
package io.contexa.contexaidentity.security.statemachine.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.identity.statemachine")
public class StateMachineProperties {

    private boolean enabled = true;

    private int operationTimeoutSeconds = 10;

    @NestedConfigurationProperty
    private CircuitBreakerProperties circuitBreaker = new CircuitBreakerProperties();

    @NestedConfigurationProperty
    private PoolProperties pool = new PoolProperties();

    @NestedConfigurationProperty
    private PersistenceProperties persistence = new PersistenceProperties();

    @NestedConfigurationProperty
    private CacheProperties cache = new CacheProperties();

    @NestedConfigurationProperty
    private EventsProperties events = new EventsProperties();

    @NestedConfigurationProperty
    private MfaProperties mfa = new MfaProperties();

    @NestedConfigurationProperty
    private RedisProperties redis = new RedisProperties();

    @NestedConfigurationProperty
    private DistributedLockProperties distributedLock = new DistributedLockProperties();

    @Data
    public static class CircuitBreakerProperties {
        
        private int failureThreshold = 5;

        private int timeoutSeconds = 30;

        private int halfOpenRequests = 3;
    }

    @Data
    public static class PoolProperties {
        
        private int coreSize = 10;

        private int maxSize = 50;

        private long keepAliveTime = 10;

        private double expansionThreshold = 0.8;

        private double shrinkThreshold = 0.2;
    }

    @Data
    public static class PersistenceProperties {
        
        private String type = "memory";

        private boolean enableFallback = true;

        private Integer ttlMinutes = 30;

        private boolean enableCompression = true;

        private int compressionThreshold = 1024;
    }

    @Data
    public static class CacheProperties {
        
        private int maxSize = 1000;

        private int ttlMinutes = 5;

        private boolean enableWarmup = false;
    }

    @Data
    public static class EventsProperties {
        
        private boolean enabled = true;

        private String type = "local";

        private int batchSize = 100;

        private int batchIntervalMs = 100;

        private int backpressureThreshold = 1000;
    }

    @Data
    public static class MfaProperties {
        
        private boolean enableMetrics = true;

        private Integer maxRetries = 3;

        private Integer sessionTimeoutMinutes = 30;

        private Integer maxConcurrentSessions = 1000;

        private Integer transitionTimeoutSeconds = 30;
    }

    @Data
    public static class RedisProperties {
        
        private boolean enabled = false;

        private Integer ttlMinutes = 30;

        private String keyPrefix = "mfa:statemachine:";

        private int connectionTimeoutMs = 2000;

        private int commandTimeoutMs = 1000;
    }

    @Data
    public static class DistributedLockProperties {
        
        private boolean enabled = true;

        private int timeoutSeconds = 10;

        private int lockWaitTimeSeconds = 10;

        private int lockLeaseTimeSeconds = 30;

        private int userRequestLockWaitTimeMs = 750;

        private int maxRetryAttempts = 3;

        private int retryIntervalMs = 100;

        private boolean enableDeadlockDetection = true;
    }
}
