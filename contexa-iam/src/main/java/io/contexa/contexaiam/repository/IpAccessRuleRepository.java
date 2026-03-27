package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.IpAccessRule;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IpAccessRuleRepository extends JpaRepository<IpAccessRule, Long> {

    List<IpAccessRule> findByEnabledTrueOrderByCreatedAtDesc();

    List<IpAccessRule> findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType ruleType);

    Page<IpAccessRule> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<IpAccessRule> findByRuleTypeOrderByCreatedAtDesc(IpAccessRule.RuleType ruleType, Pageable pageable);

    long countByRuleTypeAndEnabledTrue(IpAccessRule.RuleType ruleType);

    boolean existsByIpAddressAndRuleType(String ipAddress, IpAccessRule.RuleType ruleType);
}
