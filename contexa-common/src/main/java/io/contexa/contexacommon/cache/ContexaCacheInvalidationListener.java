package io.contexa.contexacommon.cache;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Contexa 분산 캐시 무효화 리스너
 *
 * Redis Pub/Sub를 통해 다른 노드에서 발생한 캐시 무효화 이벤트를 수신하고
 * 로컬 L1 캐시를 무효화합니다.
 *
 * 메시지 형식:
 * - "INVALIDATE_ALL": 전체 캐시 무효화
 * - "policies:*": 패턴 기반 무효화
 * - "users:authorities:admin": 특정 키 무효화
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@RequiredArgsConstructor
public class ContexaCacheInvalidationListener {

    private final ContexaCacheService cacheService;
    private final ContexaCacheProperties properties;

    /**
     * Redis Pub/Sub 메시지 수신 핸들러
     *
     * MessageListenerAdapter에 의해 호출됩니다.
     *
     * @param message 무효화 대상 키 또는 패턴
     * @param channel Pub/Sub 채널명
     */
    public void handleMessage(String message, String channel) {
        if (!properties.getPubsub().getChannel().equals(channel)) {
            log.trace("다른 채널 메시지 무시: {}", channel);
            return;
        }

        log.debug("분산 캐시 무효화 이벤트 수신 - channel: {}, message: {}", channel, message);

        try {
            if ("INVALIDATE_ALL".equals(message)) {
                // 전체 캐시 무효화
                cacheService.invalidateLocalOnly("*");
                log.info("전체 L1 캐시 무효화 완료 (분산 이벤트)");
            } else {
                // 특정 키 또는 패턴 무효화
                cacheService.invalidateLocalOnly(message);
                log.debug("L1 캐시 무효화 완료 (분산 이벤트): {}", message);
            }
        } catch (Exception e) {
            log.error("분산 캐시 무효화 실패 - message: {}", message, e);
        }
    }

    /**
     * 수신된 메시지가 유효한 무효화 명령인지 검증
     *
     * @param message 검증할 메시지
     * @return 유효 여부
     */
    private boolean isValidInvalidationMessage(String message) {
        if (message == null || message.trim().isEmpty()) {
            return false;
        }

        // INVALIDATE_ALL 또는 키/패턴 형식
        return "INVALIDATE_ALL".equals(message) || message.contains(":");
    }
}
