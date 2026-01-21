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

        
        try {
            if ("INVALIDATE_ALL".equals(message)) {
                cacheService.invalidateLocalOnly("*");
            } else {
                cacheService.invalidateLocalOnly(message);
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
