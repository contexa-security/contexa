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
@ConfigurationProperties(prefix = "contexa.security.session")
public class SecuritySessionProperties {

    @NestedConfigurationProperty
    private CreateSettings create = new CreateSettings();

    @NestedConfigurationProperty
    private HeaderSettings header = new HeaderSettings();

    @NestedConfigurationProperty
    private BearerSettings bearer = new BearerSettings();

    @NestedConfigurationProperty
    private HijackSettings hijack = new HijackSettings();

    @NestedConfigurationProperty
    private CookieSettings cookie = new CookieSettings();

    @NestedConfigurationProperty
    private ThreatSettings threat = new ThreatSettings();

    @Data
    public static class CookieSettings {
        private String name = "SESSION";
    }

    @Data
    public static class CreateSettings {
        private boolean allowed = true;
    }

    @Data
    public static class HeaderSettings {
        private String name = "X-Auth-Token";
    }

    @Data
    public static class BearerSettings {
        private boolean enabled = true;
    }

    @Data
    public static class HijackSettings {
        private String channel = "security:session:hijack:event";

        @NestedConfigurationProperty
        private DetectionSettings detection = new DetectionSettings();

        @Data
        public static class DetectionSettings {
            private boolean enabled = true;
        }
    }

    @Data
    public static class ThreatSettings {
        private double ipChangeRisk = 0.4;
        private double uaChangeRisk = 0.3;
        private int rapidAccessThresholdMs = 100;
        private double rapidAccessRisk = 0.2;

        @NestedConfigurationProperty
        private ThresholdsSettings thresholds = new ThresholdsSettings();

        @Data
        public static class ThresholdsSettings {
            private double monitoring = 0.5;
            private double gracePeriod = 0.7;
            private double invalidation = 0.9;
        }
    }
}
