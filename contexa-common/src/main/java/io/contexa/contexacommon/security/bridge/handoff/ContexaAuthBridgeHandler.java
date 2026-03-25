package io.contexa.contexacommon.security.bridge.handoff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

public interface ContexaAuthBridgeHandler {

    ContexaAuthHandoffResult handoff(ContexaAuthHandoff handoff);

    default ContexaAuthHandoffResult handoff(
            @Nullable HttpServletRequest request,
            @Nullable HttpServletResponse response,
            ContexaAuthHandoff handoff) {
        return handoff(handoff);
    }
}