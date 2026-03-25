package io.contexa.contexacommon.security.bridge.handoff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

import java.util.Collection;
import java.util.Map;

public final class ContexaAuthBridge {

    @Nullable
    private static volatile ContexaAuthBridgeHandler handler;

    private ContexaAuthBridge() {
    }

    public static ContexaAuthHandoffResult handoff(Object principal) {
        return handoff(ContexaAuthHandoff.of(principal));
    }

    public static ContexaAuthHandoffResult handoff(Object principal, Collection<?> authorities) {
        return handoff(ContexaAuthHandoff.of(principal, authorities));
    }

    public static ContexaAuthHandoffResult handoff(Object principal, Collection<?> authorities, Map<String, Object> attributes) {
        return handoff(ContexaAuthHandoff.of(principal, authorities, attributes));
    }

    public static ContexaAuthHandoffResult handoff(
            HttpServletRequest request,
            HttpServletResponse response,
            Object principal) {
        return handoff(request, response, ContexaAuthHandoff.of(principal));
    }

    public static ContexaAuthHandoffResult handoff(
            HttpServletRequest request,
            HttpServletResponse response,
            Object principal,
            Collection<?> authorities) {
        return handoff(request, response, ContexaAuthHandoff.of(principal, authorities));
    }

    public static ContexaAuthHandoffResult handoff(
            HttpServletRequest request,
            HttpServletResponse response,
            Object principal,
            Collection<?> authorities,
            Map<String, Object> attributes) {
        return handoff(request, response, ContexaAuthHandoff.of(principal, authorities, attributes));
    }

    public static ContexaAuthHandoffResult handoff(ContexaAuthHandoff handoff) {
        ContexaAuthBridgeHandler currentHandler = handler;
        if (currentHandler == null) {
            throw new IllegalStateException("ContexaAuthBridge is not initialized. Ensure @EnableAISecurity is active.");
        }
        return currentHandler.handoff(handoff);
    }

    public static ContexaAuthHandoffResult handoff(
            @Nullable HttpServletRequest request,
            @Nullable HttpServletResponse response,
            ContexaAuthHandoff handoff) {
        ContexaAuthBridgeHandler currentHandler = handler;
        if (currentHandler == null) {
            throw new IllegalStateException("ContexaAuthBridge is not initialized. Ensure @EnableAISecurity is active.");
        }
        return currentHandler.handoff(request, response, handoff);
    }

    public static boolean isInitialized() {
        return handler != null;
    }

    public static void registerHandler(ContexaAuthBridgeHandler handoffHandler) {
        handler = handoffHandler;
    }

    public static void clearHandler() {
        handler = null;
    }
}