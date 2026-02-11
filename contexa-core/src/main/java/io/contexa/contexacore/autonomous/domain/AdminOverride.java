package io.contexa.contexacore.autonomous.domain;

import lombok.Builder;
import lombok.Getter;
import java.time.Instant;

@Getter
@Builder
public class AdminOverride {

    private final String overrideId;

    private final String requestId;

    private final String userId;

    private final String adminId;

    private final Instant timestamp;

    private final String originalAction;

    private final String overriddenAction;

    private final String reason;

    private final boolean approved;

    private final double originalRiskScore;

    private final double originalConfidence;

    public boolean canUpdateBaseline() {
        return approved && "ALLOW".equalsIgnoreCase(overriddenAction);
    }

    @Override
    public String toString() {
        return String.format(
            "AdminOverride{overrideId='%s', requestId='%s', userId='%s', adminId='%s', " +
            "originalAction='%s', overriddenAction='%s', approved=%s}",
            overrideId, requestId, userId, adminId,
            originalAction, overriddenAction, approved
        );
    }
}
