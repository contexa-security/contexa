package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.security.Principal;
import java.util.Map;

/**
 * SSE subscription endpoint for Zero Trust analysis notifications.
 */
@RestController
@RequestMapping("/api/aiam/sse/zero-trust")
@RequiredArgsConstructor
public class ZeroTrustSseController {

    private final ZeroTrustSsePublisher ssePublisher;

    @GetMapping(value = "/subscribe", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous";
        return ssePublisher.addEmitter(userId);
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous";
        return ResponseEntity.ok(Map.of(
                "userId", userId,
                "subscriberCount", ssePublisher.getSubscriberCount(userId)));
    }
}
