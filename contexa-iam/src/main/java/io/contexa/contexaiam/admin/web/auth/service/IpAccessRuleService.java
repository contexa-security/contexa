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

@Slf4j
@RequiredArgsConstructor
public class IpAccessRuleService {

    private final IpAccessRuleRepository ipAccessRuleRepository;

    @Transactional(readOnly = true)
    public Page<IpAccessRule> getAllRules(Pageable pageable) {
        return ipAccessRuleRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    @Transactional(readOnly = true)
    public Page<IpAccessRule> getRulesByType(IpAccessRule.RuleType type, Pageable pageable) {
        return ipAccessRuleRepository.findByRuleTypeOrderByCreatedAtDesc(type, pageable);
    }

    @Transactional
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
        return ipAccessRuleRepository.save(rule);
    }

    @Transactional
    public void deleteRule(Long id) {
        ipAccessRuleRepository.deleteById(id);
    }

    @Transactional
    public void toggleRule(Long id) {
        ipAccessRuleRepository.findById(id).ifPresent(rule -> {
            rule.setEnabled(!rule.isEnabled());
            ipAccessRuleRepository.save(rule);
        });
    }

    @Transactional(readOnly = true)
    public long countAllowRules() {
        return ipAccessRuleRepository.countByRuleTypeAndEnabledTrue(IpAccessRule.RuleType.ALLOW);
    }

    @Transactional(readOnly = true)
    public long countDenyRules() {
        return ipAccessRuleRepository.countByRuleTypeAndEnabledTrue(IpAccessRule.RuleType.DENY);
    }

    @Transactional(readOnly = true)
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
    @Transactional(readOnly = true)
    public boolean isIpDenied(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            return false;
        }

        List<IpAccessRule> denyRules = ipAccessRuleRepository
                .findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.DENY);

        LocalDateTime now = LocalDateTime.now();
        for (IpAccessRule rule : denyRules) {
            // Skip expired rules
            if (rule.getExpiresAt() != null && rule.getExpiresAt().isBefore(now)) {
                continue;
            }
            if (matchesIpOrCidr(clientIp, rule.getIpAddress())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a client IP is explicitly allowed by any active ALLOW rule.
     */
    @Transactional(readOnly = true)
    public boolean isIpAllowed(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            return false;
        }

        List<IpAccessRule> allowRules = ipAccessRuleRepository
                .findByRuleTypeAndEnabledTrueOrderByCreatedAtDesc(IpAccessRule.RuleType.ALLOW);

        LocalDateTime now = LocalDateTime.now();
        for (IpAccessRule rule : allowRules) {
            if (rule.getExpiresAt() != null && rule.getExpiresAt().isBefore(now)) {
                continue;
            }
            if (matchesIpOrCidr(clientIp, rule.getIpAddress())) {
                return true;
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public List<IpAccessRule> findAllEnabledRules() {
        return ipAccessRuleRepository.findByEnabledTrueOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
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
}
