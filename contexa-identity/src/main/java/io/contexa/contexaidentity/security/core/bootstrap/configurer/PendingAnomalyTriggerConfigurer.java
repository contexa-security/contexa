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

import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.trigger.AuthenticatedPendingAnomalyTriggerFilter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;

public class PendingAnomalyTriggerConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 116;

    private final AuthenticatedPendingAnomalyTriggerFilter authenticatedPendingAnomalyTriggerFilter;

    public PendingAnomalyTriggerConfigurer(AuthenticatedPendingAnomalyTriggerFilter authenticatedPendingAnomalyTriggerFilter) {
        this.authenticatedPendingAnomalyTriggerFilter = authenticatedPendingAnomalyTriggerFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (authenticatedPendingAnomalyTriggerFilter == null) {
            return;
        }
        fc.http().addFilterAfter(authenticatedPendingAnomalyTriggerFilter, HCADFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}