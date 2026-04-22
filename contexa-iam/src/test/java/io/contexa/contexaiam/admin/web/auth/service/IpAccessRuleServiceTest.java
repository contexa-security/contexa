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
