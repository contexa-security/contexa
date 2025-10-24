package io.contexa.contexaidentity.security.core.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Challenge DTO 반환을 담당합니다.
 */
public class ChallengeRouter {
    private final ChallengeGenerator generator;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ChallengeRouter(ChallengeGenerator generator) {
        this.generator = generator;
    }

    /**
     * 성공 챌린지를 JSON으로 응답합니다.
     */
    public void writeNextChallenge(HttpServletResponse res, FactorContext ctx) throws IOException {
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");

        // Challenge 객체 생성
        Object challenge = generator.generate(ctx);

        // 응답 본문 구성
        Map<String, Object> body = new HashMap<>();
        body.put("sessionId", ctx.getMfaSessionId());
        body.put("state", ctx.getCurrentState().name());
        body.put("challenge", challenge);

        // JSON 직렬화
        objectMapper.writeValue(res.getWriter(), body);
    }

    /**
     * 오류 정보를 JSON 으로 응답합니다.
     */
    public void writeError(HttpServletResponse res, int status, String errorCode, String message) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");

        Map<String, Object> body = new HashMap<>();
        body.put("error", errorCode);
        body.put("message", message);

        objectMapper.writeValue(res.getWriter(), body);
    }
}

