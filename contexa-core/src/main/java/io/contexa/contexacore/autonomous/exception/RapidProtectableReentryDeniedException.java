package io.contexa.contexacore.autonomous.exception;

import org.springframework.security.authorization.AuthorizationDeniedException;

public class RapidProtectableReentryDeniedException extends AuthorizationDeniedException {

    private static final long serialVersionUID = 1L;

    private final String resourceId;
    private final long windowSeconds;

    public RapidProtectableReentryDeniedException(String resourceId, long windowSeconds) {
        super(formatMessage(resourceId, windowSeconds));
        this.resourceId = resourceId;
        this.windowSeconds = windowSeconds;
    }

    public String getResourceId() {
        return resourceId;
    }

    public long getWindowSeconds() {
        return windowSeconds;
    }

    public int getHttpStatus() {
        return 429;
    }

    public String getErrorCode() {
        return "RAPID_PROTECTABLE_REENTRY";
    }

    private static String formatMessage(String resourceId, long windowSeconds) {
        return String.format(
                "Protected resource re-entry denied within %d seconds: %s",
                windowSeconds,
                resourceId != null ? resourceId : "unknown");
    }
}
