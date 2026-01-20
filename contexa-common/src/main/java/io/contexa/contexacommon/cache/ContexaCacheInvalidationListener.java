package io.contexa.contexacommon.cache;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@RequiredArgsConstructor
public class ContexaCacheInvalidationListener {

    private final ContexaCacheService cacheService;
    private final ContexaCacheProperties properties;

    
    public void handleMessage(String message, String channel) {
        if (!properties.getPubsub().getChannel().equals(channel)) {
            log.trace("다른 채널 메시지 무시: {}", channel);
            return;
        }

        log.debug("분산 캐시 무효화 이벤트 수신 - channel: {}, message: {}", channel, message);

        try {
            if ("INVALIDATE_ALL".equals(message)) {
                
                cacheService.invalidateLocalOnly("*");
                log.info("전체 L1 캐시 무효화 완료 (분산 이벤트)");
            } else {
                
                cacheService.invalidateLocalOnly(message);
                log.debug("L1 캐시 무효화 완료 (분산 이벤트): {}", message);
            }
        } catch (Exception e) {
            log.error("분산 캐시 무효화 실패 - message: {}", message, e);
        }
    }

    
    private boolean isValidInvalidationMessage(String message) {
        if (message == null || message.trim().isEmpty()) {
            return false;
        }

        
        return "INVALIDATE_ALL".equals(message) || message.contains(":");
    }
}
