package io.contexa.contexaiam.aiam.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.security.Principal;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Controller
public class WebSocketTestMessageController {

    private final SimpMessagingTemplate brokerTemplate;

    public WebSocketTestMessageController(@Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.brokerTemplate = brokerTemplate;
    }

    // ★ 클라이언트 구독과 "완전히" 동일해야 함
    private static final String USER_PONG_DEST = "/queue/test/pong";
    private static final String TOPIC_BROADCAST = "/topic/test";

    @MessageMapping("/test/ping")
    public void handlePing(@Payload Map<String, Object> payload,
                           SimpMessageHeaderAccessor headers,
                           Principal principal) {

        String userName = principal != null ? principal.getName()
                : (headers.getUser() != null ? headers.getUser().getName() : null);
        String sessionId = headers.getSessionId();

        log.info("🏓 [TEST] PING in: payload={}, user={}, session={}", payload, userName, sessionId);

        Map<String, Object> pong = new HashMap<>();
        pong.put("type", "PONG");
        pong.put("echo", payload.get("message"));
        pong.put("serverTime", System.currentTimeMillis());
        pong.put("timestamp", OffsetDateTime.now().toString());

        // ★ 요청 보낸 세션/사용자에게만 회신 (/user/queue/test/pong) — 문자열 오탈자 금지
        if (userName != null) {
            log.info("➡️  sendToUser name='{}' dest='{}'", userName, USER_PONG_DEST);
            brokerTemplate.convertAndSendToUser(userName, USER_PONG_DEST, pong);
        } else {
            // HandshakeHandler 가 Principal을 주입하므로 일반적으로 도달 X
            log.info("➡️  sendToUser (fallback by sessionId) session='{}' dest='{}'", sessionId, USER_PONG_DEST);
            var replyHeaders = SimpMessageHeaderAccessor.create();
            replyHeaders.setSessionId(sessionId);
            replyHeaders.setLeaveMutable(true);
            brokerTemplate.convertAndSendToUser(sessionId, USER_PONG_DEST, pong, replyHeaders.getMessageHeaders());
        }

        // (옵션) 브로드캐스트
        Map<String, Object> broadcast = new HashMap<>();
        broadcast.put("type", "BROADCAST");
        broadcast.put("echo", payload.get("message"));
        broadcast.put("serverTime", System.currentTimeMillis());
        broadcast.put("timestamp", OffsetDateTime.now().toString());
        log.info("📣  broadcast dest='{}'", TOPIC_BROADCAST);
        brokerTemplate.convertAndSend(TOPIC_BROADCAST, broadcast);

        log.info("[TEST] sent user='{}' session='{}' -> /user{}  &  {}",
                userName, sessionId, USER_PONG_DEST, TOPIC_BROADCAST);
    }
}
