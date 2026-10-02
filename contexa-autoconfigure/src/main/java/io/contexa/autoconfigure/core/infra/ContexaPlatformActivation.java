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
package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import org.springframework.core.env.Environment;

/**
 * Single activation criterion for the Contexa platform inside a host application.
 *
 * <p>The platform is active once {@code @EnableAISecurity} has published
 * {@link AiSecurityImportSelector#PROP_MODE} into the Environment. Adding the starter dependency
 * alone must leave the host application untouched, so every component that changes host-visible
 * behavior outside the {@code contexa.*} namespace checks this criterion.</p>
 */
public final class ContexaPlatformActivation {

    public static final String ACTIVATION_PROPERTY = AiSecurityImportSelector.PROP_MODE;

    private ContexaPlatformActivation() {
    }

    public static boolean isActive(Environment environment) {
        return environment != null && environment.containsProperty(ACTIVATION_PROPERTY);
    }
}
