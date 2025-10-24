package io.contexa.contexaidentity.security.core.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public record FlowContext(AuthenticationFlowConfig flow, HttpSecurity http,
                          PlatformContext context, PlatformConfig config) { }

