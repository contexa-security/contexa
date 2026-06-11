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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexaiam.domain.entity.IpAccessRule;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IpAccessRuleServiceTest {

    private final IpAccessRuleRepository repository = mock(IpAccessRuleRepository.class);
    private final IpAccessRuleService service = new IpAccessRuleService(repository);

    @Test
    void reportsActiveAllowRulesOnlyWhenAtLeastOneAllowRuleIsNotExpired() {
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.ALLOW))
                .thenReturn(List.of(
                        allowRule("198.51.100.10", LocalDateTime.now().minusMinutes(1)),
                        allowRule("203.0.113.10", LocalDateTime.now().plusMinutes(10))));

        assertThat(service.hasActiveAllowRules()).isTrue();
    }

    @Test
    void reportsNoActiveAllowRulesWhenAllAllowRulesAreExpired() {
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.ALLOW))
                .thenReturn(List.of(allowRule("203.0.113.10", LocalDateTime.now().minusMinutes(1))));

        assertThat(service.hasActiveAllowRules()).isFalse();
    }

    @Test
    void matchesAllowedCidrRulesAndSkipsExpiredAllowRules() {
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.ALLOW))
                .thenReturn(List.of(
                        allowRule("198.51.100.0/24", LocalDateTime.now().minusMinutes(1)),
                        allowRule("203.0.113.0/24", LocalDateTime.now().plusMinutes(10))));

        assertThat(service.isIpAllowed("203.0.113.42")).isTrue();
        assertThat(service.isIpAllowed("198.51.100.42")).isFalse();
    }

    @Test
    void matchesDeniedCidrRulesAndSkipsExpiredDenyRules() {
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY))
                .thenReturn(List.of(
                        denyRule("198.51.100.0/24", LocalDateTime.now().minusMinutes(1)),
                        denyRule("203.0.113.0/24", LocalDateTime.now().plusMinutes(10))));

        assertThat(service.isIpDenied("203.0.113.42")).isTrue();
        assertThat(service.isIpDenied("198.51.100.42")).isFalse();
    }

    private IpAccessRule allowRule(String ipAddress, LocalDateTime expiresAt) {
        return rule(ipAddress, IpAccessRule.RuleType.ALLOW, expiresAt);
    }

    private IpAccessRule denyRule(String ipAddress, LocalDateTime expiresAt) {
        return rule(ipAddress, IpAccessRule.RuleType.DENY, expiresAt);
    }

    private IpAccessRule rule(String ipAddress, IpAccessRule.RuleType ruleType, LocalDateTime expiresAt) {
        return IpAccessRule.builder()
                .ipAddress(ipAddress)
                .ruleType(ruleType)
                .expiresAt(expiresAt)
                .enabled(true)
                .build();
    }
}
