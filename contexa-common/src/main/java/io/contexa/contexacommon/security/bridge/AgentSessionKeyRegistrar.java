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
package io.contexa.contexacommon.security.bridge;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/** Registers the configured token claim names for {@link AgentSessionKey}, and clears them when the context closes. */
public class AgentSessionKeyRegistrar implements InitializingBean, DisposableBean {

    private final BridgeProperties bridgeProperties;

    public AgentSessionKeyRegistrar(BridgeProperties bridgeProperties) {
        this.bridgeProperties = bridgeProperties;
    }

    @Override
    public void afterPropertiesSet() {
        AgentSessionKey.configure(bridgeProperties != null && bridgeProperties.getDelegation() != null
                ? bridgeProperties.getDelegation().getToken()
                : null);
    }

    @Override
    public void destroy() {
        AgentSessionKey.configure(null);
    }
}
