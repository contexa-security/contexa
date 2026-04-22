package io.contexa.contexaiam.admin.web.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import lombok.Data;

import java.time.LocalDateTime;

public final class BlacklistApiDtos {

    private BlacklistApiDtos() {
    }

    public record BlockedUserResponse(
            Long id,
            String userId,
            String username,
            String requestId,
            Double riskScore,
            Double confidence,
            String reasoning,
            String blockedAt,
            String resolvedAt,
            String resolvedBy,
            String resolvedAction,
            String resolveReason,
            Integer blockCount,
            String status,
            String sourceIp,
            String userAgent,
            String unblockRequestedAt,
            String unblockReason,
            Boolean mfaVerified,
            String mfaVerifiedAt
    ) {
        public static BlockedUserResponse from(BlockedUser blockedUser) {
            return new BlockedUserResponse(
                    blockedUser.getId(),
                    blockedUser.getUserId(),
                    blockedUser.getUsername(),
                    blockedUser.getRequestId(),
                    blockedUser.getRiskScore(),
                    blockedUser.getConfidence(),
                    blockedUser.getReasoning(),
                    dateTime(blockedUser.getBlockedAt()),
                    dateTime(blockedUser.getResolvedAt()),
                    blockedUser.getResolvedBy(),
                    blockedUser.getResolvedAction(),
                    blockedUser.getResolveReason(),
                    blockedUser.getBlockCount(),
                    blockedUser.getStatus() != null ? blockedUser.getStatus().name() : null,
                    blockedUser.getSourceIp(),
                    blockedUser.getUserAgent(),
                    dateTime(blockedUser.getUnblockRequestedAt()),
                    blockedUser.getUnblockReason(),
                    blockedUser.getMfaVerified(),
                    dateTime(blockedUser.getMfaVerifiedAt())
            );
        }

        private static String dateTime(LocalDateTime value) {
            return value != null ? value.toString() : null;
        }
    }

    @Data
    public static class ResolveBlockRequest {
        private String resolvedAction;
        private String reason;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record BlacklistActionResponse(
            Boolean success,
            Long id,
            String resolvedAction,
            String error
    ) {
        public static BlacklistActionResponse resolved(Long id, String resolvedAction) {
            return new BlacklistActionResponse(true, id, resolvedAction, null);
        }

        public static BlacklistActionResponse deleted(Long id) {
            return new BlacklistActionResponse(true, id, null, null);
        }

        public static BlacklistActionResponse failed(String error) {
            return new BlacklistActionResponse(false, null, null, error);
        }
    }
}
