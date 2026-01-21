package io.contexa.contexacore.security.session;

import jakarta.servlet.http.HttpServletRequest;

public interface SessionIdResolver {

    String resolve(HttpServletRequest request);

    boolean isValid(String sessionId);

    SessionSource getSource(HttpServletRequest request);

    enum SessionSource {
        COOKIE("Cookie에서 추출"),
        HEADER("HTTP Header에서 추출"),
        ATTRIBUTE("Request Attribute에서 추출"),
        BEARER("Bearer Token에서 추출"),
        NONE("세션 ID 없음");

        private final String description;

        SessionSource(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}