package io.contexa.contexacommon.security.bridge.sync;

public record BridgeUserShadowSyncResult(
        Long internalUserId,
        String internalUsername,
        String externalSubjectId,
        String bridgeSubjectKey,
        boolean bridgeManaged,
        boolean externalAuthOnly,
        boolean created,
        boolean updated
) {
}
