package io.contexa.contexacore.infra.session.generator;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;

public interface SessionIdGenerator {

    String generate(@Nullable String baseId, HttpServletRequest request);

    boolean isValidFormat(String sessionId);

    String resolveCollision(String originalId, int attempt, HttpServletRequest request);
}
