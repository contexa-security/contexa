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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * What an application whose sign-in Contexa owns is told before anything of it starts: a chain of its own is refused from
 * the bean definitions, before Contexa connects to its database. {@link OwnershipStartupDiagnostics} refuses what that
 * cannot be certain of, once every bean exists, as before.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class ContexaOwnedDiagnosticsConfiguration {

    @Bean(name = "contexaOwnedChainDefinitionCheck")
    public static ContexaOwnedChainDefinitionCheck contexaOwnedChainDefinitionCheck() {
        return new ContexaOwnedChainDefinitionCheck();
    }
}
