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
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionAttribute;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

    /**
     * PR-196: every request asks these three, and none of them opens a transaction of its own: the rules the cache holds
     * are still enforced while Contexa's database does not answer.
     */
    @Test
    void whatEveryRequestAsksOpensNoTransactionOfItsOwn() throws Exception {
        AnnotationTransactionAttributeSource attributes = new AnnotationTransactionAttributeSource();

        for (Method asked : List.of(
                IpAccessRuleService.class.getMethod("isIpDenied", String.class),
                IpAccessRuleService.class.getMethod("isIpAllowed", String.class),
                IpAccessRuleService.class.getMethod("hasActiveAllowRules"))) {
            TransactionAttribute attribute = attributes.getTransactionAttribute(asked, IpAccessRuleService.class);

            assertThat(attribute).as(asked.getName()).isNotNull();
            assertThat(attribute.getPropagationBehavior()).as(asked.getName())
                    .isEqualTo(TransactionDefinition.PROPAGATION_SUPPORTS);
        }
    }

    @Test
    void theRulesAreReadFromTheStoreOnceAndAnsweredFromTheCacheAfterThat() {
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY))
                .thenReturn(List.of(denyRule("203.0.113.0/24", LocalDateTime.now().plusMinutes(10))));

        assertThat(service.isIpDenied("203.0.113.42")).isTrue();
        assertThat(service.isIpDenied("203.0.113.43")).isTrue();

        verify(repository, times(1)).findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY);
    }

    private IpAccessRule allowRule(String ipAddress, LocalDateTime expiresAt) {
        return rule(ipAddress, IpAccessRule.RuleType.ALLOW, expiresAt);
    }

    private IpAccessRule denyRule(String ipAddress, LocalDateTime expiresAt) {
        return rule(ipAddress, IpAccessRule.RuleType.DENY, expiresAt);
    }

    /** IAM-D45: an ALLOW rule that leaves out the address of the administrator saving it is refused. */
    @Test
    void refusesAnAllowListWithoutTheRequestersAddress() {
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of());

        assertThatThrownBy(() -> service.createRule("203.0.113.0/24", IpAccessRule.RuleType.ALLOW, null, "admin", null,
                "127.0.0.1"))
                .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class)
                .extracting("messageKey").isEqualTo("admin.ip.refused.allow.self");
        verify(repository, never()).save(any());
    }

    /** IAM-D45: a DENY rule that matches the requester, 0.0.0.0/0 among them, is refused. */
    @Test
    void refusesADenyRuleThatMatchesTheRequester() {
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of());

        for (String denied : List.of("0.0.0.0/0", "127.0.0.0/8", "127.0.0.1")) {
            assertThatThrownBy(() -> service.createRule(denied, IpAccessRule.RuleType.DENY, null, "admin", null,
                    "127.0.0.1"))
                    .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class)
                    .extracting("messageKey").isEqualTo("admin.ip.refused.deny.self");
        }
        verify(repository, never()).save(any());
    }

    @Test
    void keepsRulesThatLeaveTheRequesterIn() {
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of());
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service.createRule("198.51.100.7", IpAccessRule.RuleType.DENY, null, "admin", null, "127.0.0.1");
        service.createRule("127.0.0.0/8", IpAccessRule.RuleType.ALLOW, null, "admin", null, "127.0.0.1");

        verify(repository, times(2)).save(any());
    }

    /** IAM-D44: a rule that has already expired is no rule; it is refused, not kept as created. */
    @Test
    void refusesAnExpiryThatHasPassed() {
        assertThatThrownBy(() -> service.createRule("198.51.100.7", IpAccessRule.RuleType.DENY, null, "admin",
                LocalDateTime.of(2000, 1, 1, 0, 0), "127.0.0.1"))
                .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class)
                .extracting("messageKey").isEqualTo("admin.ip.expires.past");
        verify(repository, never()).save(any());
    }

    /** IAM-D45: deleting or turning off the rule that keeps the requester on the allow list is refused. */
    @Test
    void refusesTakingTheRequesterOffTheAllowList() {
        IpAccessRule mine = withId(rule("127.0.0.1", IpAccessRule.RuleType.ALLOW, null), 1L);
        IpAccessRule office = withId(rule("203.0.113.0/24", IpAccessRule.RuleType.ALLOW, null), 2L);
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of(mine, office));
        when(repository.findById(1L)).thenReturn(Optional.of(mine));
        when(repository.findById(2L)).thenReturn(Optional.of(office));

        assertThatThrownBy(() -> service.deleteRule(1L, "127.0.0.1"))
                .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class);
        assertThatThrownBy(() -> service.toggleRule(1L, "127.0.0.1"))
                .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class);
        service.deleteRule(2L, "127.0.0.1");

        verify(repository).delete(office);
        verify(repository, never()).delete(mine);
        assertThat(mine.isEnabled()).isTrue();
    }

    /** IAM-D45: turning on a DENY rule that matches the requester is refused like creating one. */
    @Test
    void refusesTurningOnADenyRuleThatMatchesTheRequester() {
        IpAccessRule everyone = withId(rule("0.0.0.0/0", IpAccessRule.RuleType.DENY, null), 3L);
        everyone.setEnabled(false);
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of());
        when(repository.findById(3L)).thenReturn(Optional.of(everyone));

        assertThatThrownBy(() -> service.toggleRule(3L, "127.0.0.1"))
                .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class)
                .extracting("messageKey").isEqualTo("admin.ip.refused.deny.self");
        assertThat(everyone.isEnabled()).isFalse();
    }

    /** A requester the rules shut out already is not made worse by a change, and may repair the rules. */
    @Test
    void letsARequesterShutOutAlreadyRepairTheRules() {
        IpAccessRule office = withId(rule("203.0.113.0/24", IpAccessRule.RuleType.ALLOW, null), 2L);
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of(office));
        when(repository.findById(2L)).thenReturn(Optional.of(office));

        service.deleteRule(2L, "127.0.0.1");

        verify(repository).delete(office);
    }

    @Test
    void refusesARuleThatDoesNotExist() {
        when(repository.findById(9L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteRule(9L, "127.0.0.1"))
                .isInstanceOf(IpAccessRuleService.IpRuleRefusedException.class)
                .extracting("messageKey").isEqualTo("admin.ip.not.found");
    }

    /** IAM-D45/D80: a change made here replaces the copy in memory and is announced to the other nodes. */
    @Test
    void aChangeReplacesTheCopyAndIsAnnounced() {
        List<IpAccessRule> stored = new ArrayList<>();
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY)).thenAnswer(
                invocation -> List.copyOf(stored));
        when(repository.findByEnabledTrueOrderByCreatedAtDesc()).thenReturn(List.of());
        when(repository.save(any())).thenAnswer(invocation -> {
            stored.add(invocation.getArgument(0));
            return invocation.getArgument(0);
        });
        AtomicInteger announced = new AtomicInteger();
        service.onRulesChanged(announced::incrementAndGet);

        assertThat(service.isIpDenied("198.51.100.7")).isFalse();
        service.createRule("198.51.100.7", IpAccessRule.RuleType.DENY, null, "admin", null, "127.0.0.1");

        assertThat(service.isIpDenied("198.51.100.7")).isTrue();
        assertThat(announced).hasValue(1);
    }

    /** IAM-D45/D80: a change another node or the database made is read once the copy is dropped. */
    @Test
    void aRefreshReadsTheRulesAgain() {
        List<IpAccessRule> stored = new ArrayList<>(List.of(rule("198.51.100.7", IpAccessRule.RuleType.DENY, null)));
        when(repository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY)).thenAnswer(
                invocation -> List.copyOf(stored));
        assertThat(service.isIpDenied("198.51.100.7")).isTrue();

        stored.clear();
        assertThat(service.isIpDenied("198.51.100.7")).as("the copy in memory, within its interval").isTrue();
        service.refresh();

        assertThat(service.isIpDenied("198.51.100.7")).isFalse();
    }

    private static IpAccessRule withId(IpAccessRule rule, Long id) {
        rule.setId(id);
        return rule;
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
