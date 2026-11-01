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
package io.contexa.contexacore.security.async;

import io.contexa.contexacore.testsupport.AdjustableClock;

import java.time.Duration;

class InMemoryAsyncSecurityContextProviderContractTest extends AbstractAsyncSecurityContextProviderContractTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryAsyncSecurityContextProvider provider = new InMemoryAsyncSecurityContextProvider(clock);

    @Override
    protected AsyncSecurityContextProvider provider() {
        return provider;
    }

    @Override
    protected void elapse(Duration elapsed) {
        clock.advance(elapsed);
    }
}
