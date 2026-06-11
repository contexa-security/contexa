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
package io.contexa.contexaiam.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.iam.admin")
public class IamAdminProperties {

    private String restDocsPath = "/docs/index.html";

    @NestedConfigurationProperty
    private ConditionTemplates conditionTemplates = new ConditionTemplates();

    @Data
    public static class ConditionTemplates {

        // Opt-in flag. When false, the automatic condition template generation path
        // triggered on application startup is skipped. Manual admin endpoints remain
        // unaffected.
        private boolean enabled = false;
    }
}
