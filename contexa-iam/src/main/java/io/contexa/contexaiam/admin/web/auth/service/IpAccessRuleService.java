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

import java.util.Locale;
import io.contexa.contexaiam.domain.entity.IpAccessRule;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Keeps the IP access rules of the console and answers the filter from a copy in memory. The copy follows the database:
 * a change made here replaces it once the change is committed and is announced to the other nodes
 * ({@link #onRulesChanged}); a change made elsewhere (another node that cannot announce, the database itself) is read
 * within {@link #RULES_TTL_SECONDS} seconds.
 *
 * <p>A change that would shut out the administrator making it is refused: a DENY rule that matches the address the
 * request comes from, or an allow list that would no longer hold it. A console only the database can open again is no
 * console.</p>
 */
@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class IpAccessRuleService {

    /** How long the copy in memory is used before the rules are read again. */
    public static final long RULES_TTL_SECONDS = 10;

    private static final long RULES_TTL_NANOS = TimeUnit.SECONDS.toNanos(RULES_TTL_SECONDS);

    private final IpAccessRuleRepository ipAccessRuleRepository;

    private volatile RuleSnapshot snapshot;
    private volatile Runnable rulesChanged = () -> { };
    private final ReentrantLock reading = new ReentrantLock();
    private final AtomicLong generation = new AtomicLong();

    /** The enabled rules as read at one moment. */
    private record RuleSnapshot(List<IpAccessRule> deny, List<IpAccessRule> allow, long readAtNanos) {

        boolean fresh(long now) {
            return now - readAtNanos < RULES_TTL_NANOS;
        }
    }

    /**
     * A change of the rules refused, with the message that says why: a key and its arguments.
     */
    public static final class IpRuleRefusedException extends IllegalStateException {

        private final String messageKey;
        private final Object[] messageArgs;

        public IpRuleRefusedException(String messageKey, Object... messageArgs) {
            super("IP rule change refused: " + messageKey);
            this.messageKey = messageKey;
            this.messageArgs = messageArgs;
        }

        public String getMessageKey() {
            return messageKey;
        }

        public Object[] getMessageArgs() {
            return messageArgs.clone();
        }
    }

    /**
     * Sets what runs once a change of the rules made here is committed, as the announcement to the other nodes.
     */
    public void onRulesChanged(Runnable hook) {
        this.rulesChanged = hook != null ? hook : () -> { };
    }

    /** Drops the copy in memory, so that the next request reads the rules: another node changed them. */
    public void refresh() {
        invalidateCache();
    }

    private void invalidateCache() {
        generation.incrementAndGet();
        snapshot = null;
    }

    /**
     * The rules from the copy in memory, read again once it is past its interval. While one request reads them again the
     * others are answered from the copy, so a database that does not answer holds up that one request only (PR-196); a
     * copy dropped while the rules were being read is not put back, the next request reads them again.
     */
    private RuleSnapshot rules() {
        RuleSnapshot current = snapshot;
        if (current != null && current.fresh(System.nanoTime())) {
            return current;
        }
        if (current == null) {
            reading.lock();
        } else if (!reading.tryLock()) {
            return current;
        }
        try {
            current = snapshot;
            long now = System.nanoTime();
            if (current != null && current.fresh(now)) {
                return current;
            }
            long readFor = generation.get();
            RuleSnapshot read;
            try {
                read = new RuleSnapshot(
                        List.copyOf(ipAccessRuleRepository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY)),
                        List.copyOf(ipAccessRuleRepository.findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.ALLOW)),
                        now);
            } catch (RuntimeException e) {
                if (current == null) {
                    throw e;
                }
                // the rules read last stay in force rather than none; they are read again after the next interval
                log.warn("IP access rules could not be read again; the rules read last stay in force: {}", e.toString());
                read = new RuleSnapshot(current.deny(), current.allow(), now);
            }
            if (generation.get() == readFor) {
                snapshot = read;
            }
            return read;
        } finally {
            reading.unlock();
        }
    }

    private List<IpAccessRule> getDenyRules() {
        return rules().deny();
    }

    private List<IpAccessRule> getAllowRules() {
        return rules().allow();
    }

    /**
     * Replaces the copy in memory now and once more when the change is committed (a request in between reads what is
     * not yet committed), then announces the change to the other nodes.
     */
    private void rulesChangedHere() {
        invalidateCache();
        Runnable committed = () -> {
            invalidateCache();
            try {
                rulesChanged.run();
            } catch (RuntimeException e) {
                log.error("The change of the IP access rules could not be announced to the other nodes", e);
            }
        };
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    committed.run();
                }
            });
        } else {
            committed.run();
        }
    }

    /**
     * Refuses a change after which the address the request comes from would be shut out where it is let in now: by a
     * DENY rule that matches it, or by an allow list without it. An address the rules shut out already is not made
     * worse by the change, and whoever reached the console that way may still repair the rules.
     *
     * @param before the enabled rules now
     * @param after  the enabled rules once the change is made
     */
    private static void refuseShuttingOut(String requesterIp, List<IpAccessRule> before, List<IpAccessRule> after) {
        LocalDateTime now = LocalDateTime.now();
        if (!admits(requesterIp, before, now) || admits(requesterIp, after, now)) {
            return;
        }
        String address = StringUtils.hasText(requesterIp) ? requesterIp : "-";
        boolean denied = StringUtils.hasText(requesterIp) && after.stream().anyMatch(rule ->
                rule.getRuleType() == IpAccessRule.RuleType.DENY && isRuleActive(rule, now)
                        && matchesIpOrCidr(requesterIp, rule.getIpAddress()));
        log.warn("An IP rule change was refused: it would shut out the address it was made from: {}", address);
        throw new IpRuleRefusedException(denied ? "admin.ip.refused.deny.self" : "admin.ip.refused.allow.self", address);
    }

    /** Whether the filter lets the address in under the rules, as {@code IpAccessFilter} decides. */
    static boolean admits(String clientIp, List<IpAccessRule> rules, LocalDateTime now) {
        boolean allowList = false;
        boolean allowed = false;
        for (IpAccessRule rule : rules) {
            if (!rule.isEnabled() || !isRuleActive(rule, now)) {
                continue;
            }
            boolean matches = StringUtils.hasText(clientIp) && matchesIpOrCidr(clientIp, rule.getIpAddress());
            if (rule.getRuleType() == IpAccessRule.RuleType.DENY && matches) {
                return false;
            }
            if (rule.getRuleType() == IpAccessRule.RuleType.ALLOW) {
                allowList = true;
                allowed |= matches;
            }
        }
        return !allowList || allowed;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<IpAccessRule> getAllRules(Pageable pageable) {
        return ipAccessRuleRepository.findAllByOrderByCreatedAtDesc(pageable);
    }
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<IpAccessRule> searchRules(String type, String keyword, Pageable pageable) {
        IpAccessRule.RuleType ruleType = parseRuleType(type);
        boolean hasKeyword = StringUtils.hasText(keyword);
        String likePattern = hasKeyword ? "%" + keyword.trim().toLowerCase(Locale.ROOT) + "%" : null;

        if (hasKeyword && ruleType != null) {
            return ipAccessRuleRepository.searchByTypeAndKeyword(ruleType, likePattern, pageable);
        }
        if (hasKeyword) {
            return ipAccessRuleRepository.searchByKeyword(likePattern, pageable);
        }
        if (ruleType != null) {
            return getRulesByType(ruleType, pageable);
        }
        return getAllRules(pageable);
    }

    public String normalizeRuleTypeFilter(String type) {
        IpAccessRule.RuleType ruleType = parseRuleType(type);
        return ruleType == null ? null : ruleType.name();
    }

    private IpAccessRule.RuleType parseRuleType(String type) {
        if (!StringUtils.hasText(type)) {
            return null;
        }
        try {
            return IpAccessRule.RuleType.valueOf(type.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<IpAccessRule> getRulesByType(IpAccessRule.RuleType type, Pageable pageable) {
        return ipAccessRuleRepository.findByRuleTypeOrderByCreatedAtDesc(type, pageable);
    }

    /**
     * @param requesterIp the address the request that makes the rule comes from, as the filter reads it
     * @throws IpRuleRefusedException when the rule has already expired, or would shut out the requester
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public IpAccessRule createRule(String ipAddress, IpAccessRule.RuleType ruleType,
                                   String description, String createdBy,
                                   LocalDateTime expiresAt, String requesterIp) {
        if (expiresAt != null && !expiresAt.isAfter(LocalDateTime.now())) {
            throw new IpRuleRefusedException("admin.ip.expires.past");
        }
        IpAccessRule rule = IpAccessRule.builder()
                .ipAddress(ipAddress.trim())
                .ruleType(ruleType)
                .description(description)
                .createdBy(createdBy)
                .expiresAt(expiresAt)
                .enabled(true)
                .build();
        List<IpAccessRule> before = ipAccessRuleRepository.findByEnabledTrueOrderByCreatedAtDesc();
        List<IpAccessRule> after = new ArrayList<>(before);
        after.add(rule);
        refuseShuttingOut(requesterIp, before, after);
        IpAccessRule saved = ipAccessRuleRepository.save(rule);
        rulesChangedHere();
        return saved;
    }

    /**
     * @throws IpRuleRefusedException when no rule has the id, or the rule is the one that keeps the requester on the
     *                                allow list
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void deleteRule(Long id, String requesterIp) {
        IpAccessRule rule = ruleOf(id);
        List<IpAccessRule> before = ipAccessRuleRepository.findByEnabledTrueOrderByCreatedAtDesc();
        List<IpAccessRule> after = new ArrayList<>(before);
        after.removeIf(enabled -> id.equals(enabled.getId()));
        refuseShuttingOut(requesterIp, before, after);
        ipAccessRuleRepository.delete(rule);
        rulesChangedHere();
    }

    /**
     * @throws IpRuleRefusedException when no rule has the id, or the rule turned on or off would shut out the requester
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void toggleRule(Long id, String requesterIp) {
        IpAccessRule rule = ruleOf(id);
        List<IpAccessRule> before = ipAccessRuleRepository.findByEnabledTrueOrderByCreatedAtDesc();
        List<IpAccessRule> after = new ArrayList<>(before);
        after.removeIf(enabled -> id.equals(enabled.getId()));
        if (!rule.isEnabled()) {
            after.add(IpAccessRule.builder().id(rule.getId()).ipAddress(rule.getIpAddress()).ruleType(rule.getRuleType())
                    .expiresAt(rule.getExpiresAt()).enabled(true).build());
        }
        refuseShuttingOut(requesterIp, before, after);
        rule.setEnabled(!rule.isEnabled());
        ipAccessRuleRepository.save(rule);
        rulesChangedHere();
    }

    private IpAccessRule ruleOf(Long id) {
        return ipAccessRuleRepository.findById(id)
                .orElseThrow(() -> new IpRuleRefusedException("admin.ip.not.found", id));
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
     * Every request asks this, so it opens no transaction of its own: the rules the cache holds are answered without the
     * database and are still enforced while it does not answer.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true, propagation = Propagation.SUPPORTS)
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

    /** Asked on every request, as {@link #isIpDenied(String)} is: no transaction of its own. */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true, propagation = Propagation.SUPPORTS)
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

    /** Asked on every request, as {@link #isIpDenied(String)} is: no transaction of its own. */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true, propagation = Propagation.SUPPORTS)
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
    private static boolean matchesIpOrCidr(String clientIp, String ruleIp) {
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

    private static boolean isRuleActive(IpAccessRule rule, LocalDateTime now) {
        return rule.getExpiresAt() == null || !rule.getExpiresAt().isBefore(now);
    }
}
