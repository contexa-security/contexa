package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class IpBlockingService {
    
    private final RedisTemplate<String, Object> redisTemplate;
    
    private static final String BLOCKED_IP_KEY_PREFIX = "blocked:ip:";
    private static final String BLOCKED_IP_SET_KEY = "blocked:ip:set";
    private static final String BLOCKED_RANGE_KEY_PREFIX = "blocked:range:";
    private static final String BLOCKED_RANGE_SET_KEY = "blocked:range:set";
    private static final String WHITELIST_IP_KEY = "whitelist:ip:set";

    public BlockResult blockIp(String ipAddress, String reason, Duration duration, String blockedBy) {
        try {
            
            if (isWhitelisted(ipAddress)) {
                log.warn("Cannot block whitelisted IP: {}", ipAddress);
                return BlockResult.builder()
                    .success(false)
                    .ipAddress(ipAddress)
                    .message("IP is whitelisted and cannot be blocked")
                    .build();
            }

            if (isBlocked(ipAddress)) {
                                return BlockResult.builder()
                    .success(false)
                    .ipAddress(ipAddress)
                    .message("IP is already blocked")
                    .build();
            }
            
            BlockedIpInfo blockInfo = BlockedIpInfo.builder()
                .ipAddress(ipAddress)
                .reason(reason)
                .blockedAt(Instant.now())
                .expiresAt(duration != null ? Instant.now().plus(duration) : null)
                .blockedBy(blockedBy)
                .active(true)
                .build();

            String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
            if (duration != null) {
                redisTemplate.opsForValue().set(blockKey, blockInfo, duration.toSeconds(), TimeUnit.SECONDS);
            } else {
                redisTemplate.opsForValue().set(blockKey, blockInfo);
            }

            redisTemplate.opsForSet().add(BLOCKED_IP_SET_KEY, ipAddress);

            return BlockResult.builder()
                .success(true)
                .ipAddress(ipAddress)
                .message("IP successfully blocked")
                .blockedUntil(blockInfo.getExpiresAt())
                .build();
                
        } catch (Exception e) {
            log.error("Failed to block IP: {}", ipAddress, e);
            return BlockResult.builder()
                .success(false)
                .ipAddress(ipAddress)
                .message("Failed to block IP: " + e.getMessage())
                .build();
        }
    }

    public BlockResult blockIpRange(String cidrRange, String reason, Duration duration, String blockedBy) {
        try {
            
            if (!isValidCidr(cidrRange)) {
                return BlockResult.builder()
                    .success(false)
                    .ipAddress(cidrRange)
                    .message("Invalid CIDR range format")
                    .build();
            }
            
            BlockedRangeInfo rangeInfo = BlockedRangeInfo.builder()
                .cidrRange(cidrRange)
                .reason(reason)
                .blockedAt(Instant.now())
                .expiresAt(duration != null ? Instant.now().plus(duration) : null)
                .blockedBy(blockedBy)
                .active(true)
                .build();

            String rangeKey = BLOCKED_RANGE_KEY_PREFIX + cidrRange.replace("/", "_");
            if (duration != null) {
                redisTemplate.opsForValue().set(rangeKey, rangeInfo, duration.toSeconds(), TimeUnit.SECONDS);
            } else {
                redisTemplate.opsForValue().set(rangeKey, rangeInfo);
            }

            redisTemplate.opsForSet().add(BLOCKED_RANGE_SET_KEY, cidrRange);

            return BlockResult.builder()
                .success(true)
                .ipAddress(cidrRange)
                .message("IP range successfully blocked")
                .blockedUntil(rangeInfo.getExpiresAt())
                .build();
                
        } catch (Exception e) {
            log.error("Failed to block IP range: {}", cidrRange, e);
            return BlockResult.builder()
                .success(false)
                .ipAddress(cidrRange)
                .message("Failed to block IP range: " + e.getMessage())
                .build();
        }
    }

    public boolean unblockIp(String ipAddress) {
        try {
            String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
            Boolean deleted = redisTemplate.delete(blockKey);
            
            if (Boolean.TRUE.equals(deleted)) {
                redisTemplate.opsForSet().remove(BLOCKED_IP_SET_KEY, ipAddress);
                                return true;
            }
            
            log.warn("IP was not blocked: {}", ipAddress);
            return false;
            
        } catch (Exception e) {
            log.error("Failed to unblock IP: {}", ipAddress, e);
            return false;
        }
    }

    public boolean isBlocked(String ipAddress) {
        
        String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(blockKey))) {
            return true;
        }

        Set<Object> blockedRanges = redisTemplate.opsForSet().members(BLOCKED_RANGE_SET_KEY);
        if (blockedRanges != null) {
            for (Object range : blockedRanges) {
                if (isIpInRange(ipAddress, range.toString())) {
                    return true;
                }
            }
        }
        
        return false;
    }

    public boolean isWhitelisted(String ipAddress) {
        return Boolean.TRUE.equals(
            redisTemplate.opsForSet().isMember(WHITELIST_IP_KEY, ipAddress)
        );
    }

    public void addToWhitelist(String ipAddress) {
        redisTemplate.opsForSet().add(WHITELIST_IP_KEY, ipAddress);
            }

    public List<BlockedIpInfo> getBlockedIps() {
        Set<Object> blockedIps = redisTemplate.opsForSet().members(BLOCKED_IP_SET_KEY);
        if (blockedIps == null) {
            return Collections.emptyList();
        }
        
        return blockedIps.stream()
            .map(ip -> {
                String blockKey = BLOCKED_IP_KEY_PREFIX + ip;
                return (BlockedIpInfo) redisTemplate.opsForValue().get(blockKey);
            })
            .filter(Objects::nonNull)
            .filter(BlockedIpInfo::isActive)
            .collect(Collectors.toList());
    }

    public List<BlockedRangeInfo> getBlockedRanges() {
        Set<Object> blockedRanges = redisTemplate.opsForSet().members(BLOCKED_RANGE_SET_KEY);
        if (blockedRanges == null) {
            return Collections.emptyList();
        }
        
        return blockedRanges.stream()
            .map(range -> {
                String rangeKey = BLOCKED_RANGE_KEY_PREFIX + range.toString().replace("/", "_");
                return (BlockedRangeInfo) redisTemplate.opsForValue().get(rangeKey);
            })
            .filter(Objects::nonNull)
            .filter(BlockedRangeInfo::isActive)
            .collect(Collectors.toList());
    }

    public BlockingStatistics getStatistics() {
        int blockedIps = getBlockedIps().size();
        int blockedRanges = getBlockedRanges().size();
        int whitelistedIps = redisTemplate.opsForSet().size(WHITELIST_IP_KEY).intValue();
        
        return BlockingStatistics.builder()
            .totalBlockedIps(blockedIps)
            .totalBlockedRanges(blockedRanges)
            .totalWhitelistedIps(whitelistedIps)
            .retrievedAt(Instant.now())
            .build();
    }

    private boolean isValidCidr(String cidr) {
        if (cidr == null || !cidr.contains("/")) {
            return false;
        }
        
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            return false;
        }

        if (!isValidIpAddress(parts[0])) {
            return false;
        }

        try {
            int mask = Integer.parseInt(parts[1]);
            return mask >= 0 && mask <= 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isValidIpAddress(String ip) {
        if (ip == null) {
            return false;
        }
        
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        return true;
    }

    private boolean isIpInRange(String ip, String cidr) {
        try {
            String[] cidrParts = cidr.split("/");
            String rangeIp = cidrParts[0];
            int maskBits = Integer.parseInt(cidrParts[1]);
            
            long ipAddr = ipToLong(ip);
            long rangeAddr = ipToLong(rangeIp);
            long mask = (-1L << (32 - maskBits)) & 0xFFFFFFFFL;
            
            return (ipAddr & mask) == (rangeAddr & mask);
        } catch (Exception e) {
            log.error("Error checking IP range: {} in {}", ip, cidr, e);
            return false;
        }
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | Integer.parseInt(parts[i]);
        }
        return result;
    }

    @Data
    @Builder
    public static class BlockResult {
        private boolean success;
        private String ipAddress;
        private String message;
        private Instant blockedUntil;
    }

    @Data
    @Builder
    public static class BlockedIpInfo implements Serializable {
        private String ipAddress;
        private String reason;
        private Instant blockedAt;
        private Instant expiresAt;
        private String blockedBy;
        private boolean active;
    }

    @Data
    @Builder
    public static class BlockedRangeInfo implements Serializable {
        private String cidrRange;
        private String reason;
        private Instant blockedAt;
        private Instant expiresAt;
        private String blockedBy;
        private boolean active;
    }

    @Data
    @Builder
    public static class BlockingStatistics {
        private int totalBlockedIps;
        private int totalBlockedRanges;
        private int totalWhitelistedIps;
        private Instant retrievedAt;
    }
}