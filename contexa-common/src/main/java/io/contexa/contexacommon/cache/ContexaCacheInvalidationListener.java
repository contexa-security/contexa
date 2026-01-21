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
                        return;
        }

        
        try {
            if ("INVALIDATE_ALL".equals(message)) {
                cacheService.invalidateLocalOnly("*");
            } else {
                cacheService.invalidateLocalOnly(message);
             }
        } catch (Exception e) {
            log.error("Distributed cache invalidation failed - message: {}", message, e);
        }
    }

    
    private boolean isValidInvalidationMessage(String message) {
        if (message == null || message.trim().isEmpty()) {
            return false;
        }

        return "INVALIDATE_ALL".equals(message) || message.contains(":");
    }
}
