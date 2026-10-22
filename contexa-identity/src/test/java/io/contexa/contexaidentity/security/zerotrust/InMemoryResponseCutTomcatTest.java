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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/** RT-6 in standalone mode: the in-memory decision store and broadcaster of one JVM. */
@SpringBootTest(classes = {ResponseCutTomcatTestSupport.Web.class, InMemoryResponseCutTomcatTest.Stores.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class InMemoryResponseCutTomcatTest extends ResponseCutTomcatTestSupport {

    @Configuration(proxyBeanMethods = false)
    static class Stores {

        @Bean
        InMemoryZeroTrustActionRepository decisions() {
            return new InMemoryZeroTrustActionRepository();
        }

        @Bean
        BlockingSignalBroadcaster signals(ZeroTrustActionRepository decisions) {
            return new InMemoryBlockingSignalBroadcaster(
                    userId -> decisions.getCurrentAction(userId, null) == ZeroTrustAction.BLOCK,
                    Duration.ofMillis(500));
        }
    }
}
