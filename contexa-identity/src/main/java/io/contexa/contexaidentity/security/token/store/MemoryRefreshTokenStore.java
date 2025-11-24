package io.contexa.contexaidentity.security.token.store;

import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 메모리 기반 RefreshToken 저장소
 *
 * ConcurrentHashMap을 사용하여 단일 서버 환경에서 토큰을 관리합니다.
 * AbstractRefreshTokenStore를 상속받아 공통 로직은 재사용하고,
 * 메모리 저장소 관련 구현만 제공합니다.
 *
 * @since 2024.12 - AbstractRefreshTokenStore 상속으로 리팩토링
 * @since 2025.01 - JwtRefreshTokenStore에서 MemoryRefreshTokenStore로 이름 변경 - AbstractRefreshTokenStore 상속으로 리팩토링
 * @updated 2025.01 - JwtDecoder 기반으로 리팩토링 (RSA 지원)
 */
@Slf4j
public class MemoryRefreshTokenStore extends AbstractRefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByToken = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByDevice = new ConcurrentHashMap<>();

    public MemoryRefreshTokenStore(JwtDecoder jwtDecoder, AuthContextProperties props) {
        super(jwtDecoder, props);
    }

    @Override
    protected void doSaveToken(String username, String deviceId, String token, Instant expiration) {
        String tokenKey = deviceKey(username, deviceId);
        store.put(tokenKey, new TokenInfo(username, expiration));
    }

    @Override
    protected TokenInfo doGetTokenInfo(String username, String deviceId) {
        String tokenKey = deviceKey(username, deviceId);
        return store.get(tokenKey);
    }

    @Override
    protected void doRemoveToken(String username, String deviceId) {
        String tokenKey = deviceKey(username, deviceId);
        store.remove(tokenKey);
    }

    @Override
    protected void doBlacklistToken(String token, String username, Instant expiration, String reason) {
        blacklistByToken.put(token, new TokenInfo(username, expiration, reason));
    }

    @Override
    protected void doBlacklistDevice(String username, String deviceId, String reason) {
        String key = deviceKey(username, deviceId);
        // 디바이스 블랙리스트는 즉시 적용, 만료 시간은 현재 시간으로 설정
        blacklistByDevice.put(key, new TokenInfo(username, Instant.now(), reason));
    }

    @Override
    protected Iterable<String> doGetUserDevices(String username) {
        return store.keySet().stream()
                .filter(key -> key.startsWith(username + ":"))
                .map(key -> key.substring(username.length() + 1))
                .collect(Collectors.toList());
    }

    @Override
    protected int doGetUserDeviceCount(String username) {
        return (int) store.keySet().stream()
                .filter(key -> key.startsWith(username + ":"))
                .count();
    }

    @Override
    protected String doGetOldestDevice(String username) {
        return store.entrySet().stream()
                .filter(e -> e.getKey().startsWith(username + ":"))
                .min(Comparator.comparing(e -> e.getValue().getExpiration()))
                .map(e -> e.getKey().substring(username.length() + 1))
                .orElse(null);
    }

    @Override
    public boolean isBlacklisted(String token) {
        if (token == null) {
            return false;
        }

        // 토큰 블랙리스트 확인
        if (blacklistByToken.containsKey(token)) {
            return true;
        }

        // 디바이스 블랙리스트 확인
        try {
            // Spring Security OAuth2 표준 JwtDecoder로 RSA 서명 토큰 파싱
            Jwt jwt = jwtDecoder.decode(token);

            String subject = jwt.getSubject();
            String deviceId = jwt.getClaim("deviceId");
            if (deviceId == null) {
                return false;
            }

            String deviceKey = deviceKey(subject, deviceId);
            return blacklistByDevice.containsKey(deviceKey);

        } catch (JwtException e) {
            log.trace("JWT decoding failed during isBlacklisted check. Error: {}", e.getMessage(), e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during isBlacklisted check. Error: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 주기적으로 만료된 블랙리스트 항목 정리 (매 시간 실행)
     */
//    @Scheduled(fixedRate = 3600000)
    public void cleanupExpiredBlacklistEntries() {
        Instant now = Instant.now();

        // 만료된 토큰 블랙리스트 항목 제거
        blacklistByToken.entrySet().removeIf(entry ->
                entry.getValue().getExpiration() != null && now.isAfter(entry.getValue().getExpiration())
        );

        // 만료된 토큰 저장소 항목 제거
        store.entrySet().removeIf(entry ->
                now.isAfter(entry.getValue().getExpiration())
        );

        log.debug("Cleaned up expired entries from memory store");
    }
}