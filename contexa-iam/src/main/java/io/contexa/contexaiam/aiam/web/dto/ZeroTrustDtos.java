package io.contexa.contexaiam.aiam.web.dto;

public final class ZeroTrustDtos {

    private ZeroTrustDtos() {
    }

    public record ZeroTrustSseStatusResponse(
            String userId,
            int subscriberCount
    ) {
    }

    public sealed interface ZeroTrustActionResponse
            permits ZeroTrustMessageResponse,
                    ZeroTrustInitiateSuccessResponse,
                    ZeroTrustUnblockSuccessResponse {
    }

    public record ZeroTrustMessageResponse(
            boolean success,
            String message
    ) implements ZeroTrustActionResponse {
    }

    public record ZeroTrustInitiateSuccessResponse(
            boolean success
    ) implements ZeroTrustActionResponse {
    }

    public record ZeroTrustUnblockSuccessResponse(
            boolean success,
            boolean mfaVerified,
            String message
    ) implements ZeroTrustActionResponse {
    }
}
