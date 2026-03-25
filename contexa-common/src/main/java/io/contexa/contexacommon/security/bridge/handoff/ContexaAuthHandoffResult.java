package io.contexa.contexacommon.security.bridge.handoff;

import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import org.springframework.lang.Nullable;

public record ContexaAuthHandoffResult(
        BridgeResolutionResult resolutionResult,
        @Nullable BridgeUserMirrorSyncResult userMirrorSyncResult
) {
}