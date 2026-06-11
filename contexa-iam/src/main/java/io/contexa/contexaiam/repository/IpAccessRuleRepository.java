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
