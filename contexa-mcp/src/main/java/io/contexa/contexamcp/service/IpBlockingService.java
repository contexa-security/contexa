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

/**
 * IP Blocking Service
 * IP 주소 차단 관리 서비스
 */
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
    
    /**
     * IP 차단
     */
    public BlockResult blockIp(String ipAddress, String reason, Duration duration, String blockedBy) {
        try {
            // 화이트리스트 확인
            if (isWhitelisted(ipAddress)) {
                log.warn("Cannot block whitelisted IP: {}", ipAddress);
                return BlockResult.builder()
                    .success(false)
                    .ipAddress(ipAddress)
                    .message("IP is whitelisted and cannot be blocked")
                    .build();
            }
            
            // 이미 차단된 IP인지 확인
            if (isBlocked(ipAddress)) {
                log.info("IP already blocked: {}", ipAddress);
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
            
            // Redis에 차단 정보 저장
            String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
            if (duration != null) {
                redisTemplate.opsForValue().set(blockKey, blockInfo, duration.toSeconds(), TimeUnit.SECONDS);
            } else {
                redisTemplate.opsForValue().set(blockKey, blockInfo);
            }
            
            // 차단 IP 집합에 추가
            redisTemplate.opsForSet().add(BLOCKED_IP_SET_KEY, ipAddress);
            
            log.info("IP blocked: {} for reason: {} by: {}", ipAddress, reason, blockedBy);
            
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
    
    /**
     * IP 범위 차단 (CIDR)
     */
    public BlockResult blockIpRange(String cidrRange, String reason, Duration duration, String blockedBy) {
        try {
            // CIDR 유효성 검증
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
            
            // Redis에 범위 차단 정보 저장
            String rangeKey = BLOCKED_RANGE_KEY_PREFIX + cidrRange.replace("/", "_");
            if (duration != null) {
                redisTemplate.opsForValue().set(rangeKey, rangeInfo, duration.toSeconds(), TimeUnit.SECONDS);
            } else {
                redisTemplate.opsForValue().set(rangeKey, rangeInfo);
            }
            
            // 차단 범위 집합에 추가
            redisTemplate.opsForSet().add(BLOCKED_RANGE_SET_KEY, cidrRange);
            
            log.info("IP range blocked: {} for reason: {} by: {}", cidrRange, reason, blockedBy);
            
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
    
    /**
     * IP 차단 해제
     */
    public boolean unblockIp(String ipAddress) {
        try {
            String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
            Boolean deleted = redisTemplate.delete(blockKey);
            
            if (Boolean.TRUE.equals(deleted)) {
                redisTemplate.opsForSet().remove(BLOCKED_IP_SET_KEY, ipAddress);
                log.info("IP unblocked: {}", ipAddress);
                return true;
            }
            
            log.warn("IP was not blocked: {}", ipAddress);
            return false;
            
        } catch (Exception e) {
            log.error("Failed to unblock IP: {}", ipAddress, e);
            return false;
        }
    }
    
    /**
     * IP 차단 여부 확인
     */
    public boolean isBlocked(String ipAddress) {
        // 개별 IP 차단 확인
        String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(blockKey))) {
            return true;
        }
        
        // 범위 차단 확인
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
    
    /**
     * 화이트리스트 확인
     */
    public boolean isWhitelisted(String ipAddress) {
        return Boolean.TRUE.equals(
            redisTemplate.opsForSet().isMember(WHITELIST_IP_KEY, ipAddress)
        );
    }
    
    /**
     * 화이트리스트에 IP 추가
     */
    public void addToWhitelist(String ipAddress) {
        redisTemplate.opsForSet().add(WHITELIST_IP_KEY, ipAddress);
        log.info("IP added to whitelist: {}", ipAddress);
    }
    
    /**
     * 차단된 IP 목록 조회
     */
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
    
    /**
     * 차단된 IP 범위 목록 조회
     */
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
    
    /**
     * 차단 통계 조회
     */
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
    
    /**
     * CIDR 유효성 검증
     */
    private boolean isValidCidr(String cidr) {
        if (cidr == null || !cidr.contains("/")) {
            return false;
        }
        
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            return false;
        }
        
        // IP 부분 검증
        if (!isValidIpAddress(parts[0])) {
            return false;
        }
        
        // 서브넷 마스크 검증
        try {
            int mask = Integer.parseInt(parts[1]);
            return mask >= 0 && mask <= 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    /**
     * IP 주소 유효성 검증
     */
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
    
    /**
     * IP가 특정 범위에 포함되는지 확인
     */
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
    
    /**
     * IP 주소를 long으로 변환
     */
    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | Integer.parseInt(parts[i]);
        }
        return result;
    }
    
    /**
     * Block Result
     */
    @Data
    @Builder
    public static class BlockResult {
        private boolean success;
        private String ipAddress;
        private String message;
        private Instant blockedUntil;
    }
    
    /**
     * Blocked IP Info
     */
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
    
    /**
     * Blocked Range Info
     */
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
    
    /**
     * Blocking Statistics
     */
    @Data
    @Builder
    public static class BlockingStatistics {
        private int totalBlockedIps;
        private int totalBlockedRanges;
        private int totalWhitelistedIps;
        private Instant retrievedAt;
    }
}