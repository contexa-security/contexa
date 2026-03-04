package io.contexa.contexacore.security.session;

import jakarta.servlet.http.HttpServletRequest;

public interface SessionIdResolver {

    String resolve(HttpServletRequest request);

    boolean isValid(String sessionId);

    SessionSource getSource(HttpServletRequest request);

    enum SessionSource {
        COOKIE("Extracted from Cookie"),
        HEADER("Extracted from HTTP Header"),
        ATTRIBUTE("Extracted from Request Attribute"),
        BEARER("Extracted from Bearer Token"),
        NONE("No Session ID");

        private final String description;

        SessionSource(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}