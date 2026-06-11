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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;

public class StateConfigurerAdapter implements SecurityConfigurer {
    private final StateAdapter stateAdapter;
    private final PlatformContext ctx;

    public StateConfigurerAdapter(StateAdapter stateAdapter, PlatformContext ctx) {
        this.stateAdapter = stateAdapter;
        this.ctx = ctx;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        StateConfig state = fc.flow().getStateConfig();
        if (state != null && stateAdapter.getId().equalsIgnoreCase(state.state())) {
            stateAdapter.apply(fc.http(), ctx, fc.flow());
        }
    }

    @Override
    public int getOrder() {
        return 400;
    }
}
