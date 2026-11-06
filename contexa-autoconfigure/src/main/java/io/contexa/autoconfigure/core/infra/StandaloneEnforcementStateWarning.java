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
 * Q-6: reports at startup what a restart ends. In standalone the decisions in force live in the memory of this server, so a
 * restart ends a CHALLENGE, an ESCALATE and the ALLOW held for a user, and the next request is analyzed again. A BLOCK
 * is in memory too, but the block record of contexa-iam (ctxa_blocked_user) holds every BLOCK in force and the start
 * writes it again ({@code RestrictionRestorer}): the user stays blocked. A BLOCK nothing recorded, and every BLOCK
 * without contexa-iam, ends with the server. Standalone is for development; the distributed mode keeps them all. A
 * repository the host gives keeps the startup silent.
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
                    + "lost on restart, so a CHALLENGE, an ESCALATE and the ALLOW held for a user end with the server and "
                    + "the next request is analyzed again. A BLOCK is written again at start only from the block record of "
                    + "contexa-iam (ctxa_blocked_user): a block it holds in force stays in force, and one it does not hold, "
                    + "or any block without contexa-iam, ends with the server. Standalone is for development, set "
                    + "contexa.infrastructure.mode=distributed with Redis to keep them all.");
        }
    }
}
