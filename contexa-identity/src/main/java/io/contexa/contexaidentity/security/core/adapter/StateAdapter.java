package io.contexa.contexaidentity.security.core.adapter;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface StateAdapter {

    String getId();

    void apply(HttpSecurity http, PlatformContext ctx) throws Exception;

    default void apply(HttpSecurity http, PlatformContext ctx, AuthenticationFlowConfig flowConfig) throws Exception {
        apply(http, ctx);
    }
}

