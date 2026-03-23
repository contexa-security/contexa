package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.List;

public class CompositeAuthBridge implements AuthBridge {

    private final List<AuthBridge> delegates;

    public CompositeAuthBridge(List<AuthBridge> delegates) {
        this.delegates = delegates != null ? List.copyOf(new ArrayList<>(delegates)) : List.of();
    }

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        for (AuthBridge delegate : delegates) {
            if (delegate == null) {
                continue;
            }
            BridgedUser bridgedUser = delegate.extractUser(request);
            if (bridgedUser != null && bridgedUser.username() != null && !bridgedUser.username().isBlank()) {
                return bridgedUser;
            }
        }
        return null;
    }
}
