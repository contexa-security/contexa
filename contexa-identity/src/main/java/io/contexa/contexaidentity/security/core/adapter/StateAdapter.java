package io.contexa.contexaidentity.security.core.adapter;

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface StateAdapter {

    String getId();

    void apply(HttpSecurity http, PlatformContext ctx) throws Exception;
}

