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

import io.contexa.contexacore.infra.ContexaReactorResources;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

/**
 * The application holds the event loop and the timer of Contexa's reactive work for as long as it runs, and lets them go when it
 * closes, so that no thread of Contexa outlives it. First among Contexa's configurations: the hold is made before the beans that
 * use the threads and released after them.
 */
@AutoConfiguration
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
public class ContexaReactorResourcesAutoConfiguration {

    @Bean(name = "contexaReactorResources")
    public ContexaReactorResources.Hold contexaReactorResources() {
        return ContexaReactorResources.hold();
    }
}
