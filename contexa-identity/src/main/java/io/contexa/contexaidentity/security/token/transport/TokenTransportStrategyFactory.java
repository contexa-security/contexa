package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;

public class TokenTransportStrategyFactory {

    public static TokenTransportStrategy create(AuthContextProperties props) {
        return switch (props.getTokenTransportType()) {
            case HEADER -> new HeaderTokenStrategy(props);
            case COOKIE -> new CookieTokenStrategy(props);
            case HEADER_COOKIE -> new HeaderCookieTokenStrategy(props);
        };
    }
}

