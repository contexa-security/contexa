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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OwnershipBehaviourTest {

    @Test
    void anApplicationThatKeepsItsSignInKeepsItsChainAndItsSecurityContext() {
        OwnershipBehaviour behaviour = OwnershipBehaviour.of(SecurityOwnershipMode.HOST_OWNED);

        assertThat(behaviour.buildsSecurityChain()).isFalse();
        assertThat(behaviour.writesSecurityContext()).isFalse();
        assertThat(behaviour.enforcesFromServletFilters()).isTrue();
        assertThat(behaviour.adminIpFilterPattern()).isEqualTo("/contexa/*");
        assertThat(behaviour.consoleSignsInOnItsOwnChain()).isTrue();
    }

    @Test
    void whereContexaOwnsTheSignInItBuildsTheChainAndCoversEveryRequest() {
        OwnershipBehaviour behaviour = OwnershipBehaviour.of(SecurityOwnershipMode.CONTEXA_OWNED);

        assertThat(behaviour.buildsSecurityChain()).isTrue();
        assertThat(behaviour.writesSecurityContext()).isTrue();
        assertThat(behaviour.enforcesFromServletFilters()).isFalse();
        assertThat(behaviour.adminIpFilterPattern()).isEqualTo("/*");
        assertThat(behaviour.consoleSignsInOnItsOwnChain()).isFalse();
    }

    @Test
    void theBridgePropertiesAnswerForTheirOwnership() {
        BridgeProperties properties = new BridgeProperties();

        assertThat(properties.ownershipBehaviour()).isEqualTo(OwnershipBehaviour.HOST_OWNED);

        properties.setOwnership(SecurityOwnershipMode.CONTEXA_OWNED);

        assertThat(properties.ownershipBehaviour()).isEqualTo(OwnershipBehaviour.CONTEXA_OWNED);
    }
}
