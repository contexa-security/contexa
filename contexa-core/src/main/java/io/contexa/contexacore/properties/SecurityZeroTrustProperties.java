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

import java.time.Duration;

@Data
@ConfigurationProperties(prefix = "contexa.security.zerotrust")
public class SecurityZeroTrustProperties {

    private boolean enabled = true;

    private SecurityMode mode = SecurityMode.ENFORCE;

    private int maxBlockMfaAttempts = 2;

    public enum SecurityMode {
        SHADOW,
        ENFORCE;

        public boolean isEnforcementEnabled() {
            return this == ENFORCE;
        }
    }

    public boolean isEnforcementEnabled() {
        return mode.isEnforcementEnabled();
    }

    @NestedConfigurationProperty
    private SamplingSettings sampling = new SamplingSettings();

    @NestedConfigurationProperty
    private HotPathSettings hotpath = new HotPathSettings();

    @NestedConfigurationProperty
    private ThresholdsSettings thresholds = new ThresholdsSettings();

    @NestedConfigurationProperty
    private ProtectableSettings protectable = new ProtectableSettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private ThreatSettings threat = new ThreatSettings();

    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();

    @NestedConfigurationProperty
    private SessionSettings session = new SessionSettings();

    @NestedConfigurationProperty
    private ChallengeSettings challenge = new ChallengeSettings();

    @Data
    public static class ThreatSettings {
        private double initial = 0.3;
    }

    @Data
    public static class CacheSettings {
        private int ttlHours = 24;
        private int sessionTtlMinutes = 30;
        private int invalidatedTtlMinutes = 60;
    }

    @Data
    public static class SessionSettings {
        private boolean trackingEnabled = true;
    }

    @Data
    public static class ChallengeSettings {
        private Duration lockWaitTime = Duration.ZERO;
        private Duration lockLeaseTime = Duration.ofSeconds(30);
        private int busyRetryAfterSeconds = 3;
    }

    @Data
    public static class SamplingSettings {
        private double rate = 1.0;
    }

    @Data
    public static class HotPathSettings {
        private boolean enabled = true;
    }

    @Data
    public static class ThresholdsSettings {
        private double skip = 0.3;
        private double optional = 0.5;
        private double required = 0.7;
        private double strict = 0.9;
    }

    @Data
    public static class ProtectableSettings {
        private long rapidReentryWindowMs = 5000;
    }

    @Data
    public static class RedisSettings {
        private int timeout = 5000;
        private int updateIntervalSeconds = 30;
    }
}
