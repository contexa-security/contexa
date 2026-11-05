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

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.function.Supplier;

/**
 * Q-6: reports at startup that a restart ends the decisions in force. In standalone they live in the memory of this
 * server, so a restart lets a blocked user go on while ctxa_blocked_user still says BLOCKED, and ends a CHALLENGE.
 * Standalone is for development and nothing restores them; the distributed mode keeps them. A repository the host gives
 * keeps the startup silent.
 */
@Slf4j
public class StandaloneEnforcementStateWarning implements SmartInitializingSingleton {

    private final Supplier<ZeroTrustActionRepository> actionRepository;

    public StandaloneEnforcementStateWarning(Supplier<ZeroTrustActionRepository> actionRepository) {
        this.actionRepository = actionRepository;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (actionRepository.get() instanceof InMemoryZeroTrustActionRepository) {
            log.warn("[Contexa] contexa.infrastructure.mode is standalone: the decisions in force are kept in memory and "
                    + "lost on restart, so a BLOCK and a CHALLENGE end with the server although ctxa_blocked_user keeps its "
                    + "record; standalone is for development, set contexa.infrastructure.mode=distributed with Redis to "
                    + "keep them.");
        }
    }
}
