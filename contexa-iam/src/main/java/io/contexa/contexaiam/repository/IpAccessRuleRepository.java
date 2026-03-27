package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.IpAccessRule;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface IpAccessRuleRepository extends JpaRepository<IpAccessRule, Long> {

    List<IpAccessRule> findByEnabledTrueOrderByCreatedAtDesc();

    List<IpAccessRule> findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType ruleType);

    Page<IpAccessRule> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<IpAccessRule> findByRuleTypeOrderByCreatedAtDesc(IpAccessRule.RuleType ruleType, Pageable pageable);

    long countByRuleTypeAndEnabledTrue(IpAccessRule.RuleType ruleType);

    boolean existsByIpAddressAndRuleType(String ipAddress, IpAccessRule.RuleType ruleType);

    @Query("SELECT r FROM IpAccessRule r WHERE (lower(r.ipAddress) LIKE :keyword OR lower(r.description) LIKE :keyword) ORDER BY r.createdAt DESC")
    Page<IpAccessRule> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);

    @Query("SELECT r FROM IpAccessRule r WHERE r.ruleType = :type AND (lower(r.ipAddress) LIKE :keyword OR lower(r.description) LIKE :keyword) ORDER BY r.createdAt DESC")
    Page<IpAccessRule> searchByTypeAndKeyword(@Param("type") IpAccessRule.RuleType type, @Param("keyword") String keyword, Pageable pageable);
}
