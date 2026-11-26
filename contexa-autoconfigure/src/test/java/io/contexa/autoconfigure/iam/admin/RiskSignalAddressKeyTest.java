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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Bridge v2 B5-1: the user a risk signal names by an address is the decision key of that user, or no one. */
@DisplayName("위험 신호가 메일로 가리킨 사용자의 판정 키")
class RiskSignalAddressKeyTest {

    private final UserRepository users = mock(UserRepository.class);

    @Test
    @DisplayName("Contexa 계정의 메일이면 그 계정 아이디가 판정 키다")
    void anAccountsAddressNamesTheAccount() {
        Users account = Users.builder().id(1L).username("admin").password("x").name("Admin").build();
        when(users.findFirstByEmailIgnoreCaseAndBridgeManagedFalse("admin@corp.example")).thenReturn(Optional.of(account));

        assertThat(IamAgentRegistryAutoConfiguration.RiskSignalReceiverConfiguration
                .decisionKeyOfAddress(users, "admin@corp.example")).isEqualTo("admin");
    }

    @Test
    @DisplayName("레거시 사용자 사본 하나의 메일이면 사본 해시 이름이 아니라 그 사용자의 판정 키다")
    void oneCopysAddressNamesItsDecisionKey() {
        when(users.findByEmailIgnoreCase("kim@corp.example")).thenReturn(List.of(copy("kim01")));

        assertThat(IamAgentRegistryAutoConfiguration.RiskSignalReceiverConfiguration
                .decisionKeyOfAddress(users, "kim@corp.example")).isEqualTo("kim01");
    }

    @Test
    @DisplayName("여러 사본이 같이 쓰는 메일은 누구인지 정하지 않는다")
    void anAddressCopiesShareNamesNoOne() {
        when(users.findByEmailIgnoreCase("team@corp.example")).thenReturn(List.of(copy("kim01"), copy("lee02")));

        assertThat(IamAgentRegistryAutoConfiguration.RiskSignalReceiverConfiguration
                .decisionKeyOfAddress(users, "team@corp.example")).isNull();
    }

    private static Users copy(String decisionKey) {
        return Users.builder().username("brg_" + decisionKey).password("x").name(decisionKey).bridgeManaged(true)
                .externalSubjectId(decisionKey).build();
    }
}
