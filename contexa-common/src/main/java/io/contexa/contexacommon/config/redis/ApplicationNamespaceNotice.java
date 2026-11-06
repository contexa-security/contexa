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
package io.contexa.contexacommon.config.redis;

import io.contexa.contexacommon.store.ApplicationNamespace;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * An application that shares its Redis and its Kafka with another is told apart by {@code spring.application.name}. One
 * without a name keeps the keys and the consumer group it always had, which another application sharing the same
 * infrastructure would share with it: the start says so once, at INFO, and goes on.
 */
@Slf4j
final class ApplicationNamespaceNotice implements SmartInitializingSingleton {

    @Override
    public void afterSingletonsInstantiated() {
        if (ApplicationNamespace.isNamed()) {
            log.debug("[Contexa] Redis keys are kept under {} and the Kafka consumer group ends in .{}",
                    ApplicationNamespace.key(""), ApplicationNamespace.identifier());
            return;
        }
        log.info("[Contexa] spring.application.name is not set, so Contexa keeps its state in Redis and reads its security "
                + "events from Kafka under names that every application using the same Redis and Kafka shares: two "
                + "applications on shared infrastructure would see each other's blocks and take each other's events. "
                + "Set spring.application.name when the Redis or the Kafka is shared with another application; with "
                + "infrastructure of its own nothing needs to change.");
    }
}
