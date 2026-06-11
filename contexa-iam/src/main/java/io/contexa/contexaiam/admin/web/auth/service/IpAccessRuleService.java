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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class IpAccessRuleService {

    private final IpAccessRuleRepository ipAccessRuleRepository;

    // In-memory cache for IP rules to avoid DB query on every request
    private final AtomicReference<List<IpAccessRule>> cachedDenyRules = new AtomicReference<>();
    private final AtomicReference<List<IpAccessRule>> cachedAllowRules = new AtomicReference<>();

    private void invalidateCache() {
        cachedDenyRules.set(null);
        cachedAllowRules.set(null);
    }

    private List<IpAccessRule> getDenyRules() {
        List<IpAccessRule> cached = cachedDenyRules.get();
        if (cached == null) {
            cached = List.copyOf(ipAccessRuleRepository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY));
            cachedDenyRules.compareAndSet(null, cached);
            return cachedDenyRules.get();
        }
        return cached;
    }

    private List<IpAccessRule> getAllowRules() {
        List<IpAccessRule> cached = cachedAllowRules.get();
        if (cached == null) {
            cached = List.copyOf(ipAccessRuleRepository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.ALLOW));
            cachedAllowRules.compareAndSet(null, cached);
            return cachedAllowRules.get();
        }
        return cached;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<IpAccessRule> getAllRules(Pageable pageable) {
        return ipAccessRuleRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<IpAccessRule> getRulesByType(IpAccessRule.RuleType type, Pageable pageable) {
        return ipAccessRuleRepository.findByRuleTypeOrderByCreatedAtDesc(type, pageable);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public IpAccessRule createRule(String ipAddress, IpAccessRule.RuleType ruleType,
                                   String description, String createdBy,
                                   LocalDateTime expiresAt) {
        IpAccessRule rule = IpAccessRule.builder()
                .ipAddress(ipAddress.trim())
                .ruleType(ruleType)
                .description(description)
                .createdBy(createdBy)
                .expiresAt(expiresAt)
                .enabled(true)
                .build();
        IpAccessRule saved = ipAccessRuleRepository.save(rule);
        invalidateCache();
        return saved;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void deleteRule(Long id) {
        ipAccessRuleRepository.deleteById(id);
        invalidateCache();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void toggleRule(Long id) {
        ipAccessRuleRepository.findById(id).ifPresent(rule -> {
            rule.setEnabled(!rule.isEnabled());
            ipAccessRuleRepository.save(rule);
        });
        invalidateCache();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public long countAllowRules() {
        return ipAccessRuleRepository.countByRuleTypeAndEnabledTrue(IpAccessRule.RuleType.ALLOW);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public long countDenyRules() {
        return ipAccessRuleRepository.countByRuleTypeAndEnabledTrue(IpAccessRule.RuleType.DENY);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public boolean existsByIpAndType(String ipAddress, IpAccessRule.RuleType ruleType) {
        return ipAccessRuleRepository.existsByIpAddressAndRuleType(ipAddress, ruleType);
    }

    /**
     * Validate IP address or CIDR notation.
     * Accepts IPv4 (192.168.1.1), IPv6 (::1), and CIDR (192.168.1.0/24).
     */
    public boolean isValidIpOrCidr(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        String trimmed = ip.trim();

        // CIDR notation
        if (trimmed.contains("/")) {
            String[] parts = trimmed.split("/", 2);
            if (parts.length != 2) {
                return false;
            }
            if (!isValidInetAddress(parts[0])) {
                return false;
            }
            try {
                int prefix = Integer.parseInt(parts[1]);
                boolean isIpv6 = parts[0].contains(":");
                int maxPrefix = isIpv6 ? 128 : 32;
                return prefix >= 0 && prefix <= maxPrefix;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return isValidInetAddress(trimmed);
    }

    /**
     * Check if a client IP is denied by any active DENY rule.
     * Returns true if the IP matches any enabled DENY rule.
     */
    public boolean isIpDenied(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            return false;
        }

        LocalDateTime now = LocalDateTime.now();
        for (IpAccessRule rule : getDenyRules()) {
            if (!isRuleActive(rule, now)) {
                continue;
            }
            if (matchesIpOrCidr(clientIp, rule.getIpAddress())) {
                return true;
            }
        }
        return false;
    }

    public boolean isIpAllowed(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            return false;
        }

        LocalDateTime now = LocalDateTime.now();
        for (IpAccessRule rule : getAllowRules()) {
            if (!isRuleActive(rule, now)) {
                continue;
            }
            if (matchesIpOrCidr(clientIp, rule.getIpAddress())) {
                return true;
            }
        }
        return false;
    }

    public boolean hasActiveAllowRules() {
        LocalDateTime now = LocalDateTime.now();
        return getAllowRules().stream().anyMatch(rule -> isRuleActive(rule, now));
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<IpAccessRule> findAllEnabledRules() {
        return ipAccessRuleRepository.findByEnabledTrueOrderByCreatedAtDesc();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<IpAccessRule> findAllRules() {
        return ipAccessRuleRepository.findAll();
    }

    private boolean isValidInetAddress(String addr) {
        try {
            InetAddress inet = InetAddress.getByName(addr);
            return inet.getHostAddress().equals(addr);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Match client IP against a rule IP or CIDR.
     * For exact IP, compare directly.
     * For CIDR, compute network prefix match.
     */
    private boolean matchesIpOrCidr(String clientIp, String ruleIp) {
        try {
            if (ruleIp.contains("/")) {
                String[] parts = ruleIp.split("/", 2);
                int prefixLen = Integer.parseInt(parts[1]);

                byte[] ruleBytes = InetAddress.getByName(parts[0]).getAddress();
                byte[] clientBytes = InetAddress.getByName(clientIp).getAddress();

                if (ruleBytes.length != clientBytes.length) {
                    return false;
                }

                int fullBytes = prefixLen / 8;
                int remainBits = prefixLen % 8;

                for (int i = 0; i < fullBytes; i++) {
                    if (ruleBytes[i] != clientBytes[i]) {
                        return false;
                    }
                }

                if (remainBits > 0 && fullBytes < ruleBytes.length) {
                    int mask = (0xFF << (8 - remainBits)) & 0xFF;
                    return (ruleBytes[fullBytes] & mask) == (clientBytes[fullBytes] & mask);
                }

                return true;
            }

            // Exact match
            return clientIp.equals(ruleIp);
        } catch (Exception e) {
            log.error("IP matching error: clientIp={}, ruleIp={}", clientIp, ruleIp, e);
            return false;
        }
    }

    private boolean isRuleActive(IpAccessRule rule, LocalDateTime now) {
        return rule.getExpiresAt() == null || !rule.getExpiresAt().isBefore(now);
    }
}
