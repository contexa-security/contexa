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
@ConfigurationProperties(prefix = "contexa.advisor")
public class ContexaAdvisorProperties {

    private String chainProfile = "STANDARD";

    @NestedConfigurationProperty
    private SecurityAdvisorSettings security = new SecurityAdvisorSettings();

    @NestedConfigurationProperty
    private SoarAdvisorSettings soar = new SoarAdvisorSettings();

    @Data
    public static class SecurityAdvisorSettings {
        private boolean enabled = true;
        private int order = 50;
        private boolean requireAuthentication = false;
    }

    @Data
    public static class SoarAdvisorSettings {
        @NestedConfigurationProperty
        private ApprovalSettings approval = new ApprovalSettings();

        @Data
        public static class ApprovalSettings {
            private boolean enabled = true;
            private int order = 100;
            private int timeout = 300;
        }
    }
}
