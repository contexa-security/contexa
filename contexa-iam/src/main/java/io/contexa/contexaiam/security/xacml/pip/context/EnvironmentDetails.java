package io.contexa.contexaiam.security.xacml.pip.context;

import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;

public record EnvironmentDetails(
        String remoteIp,
        LocalDateTime timestamp,
        HttpServletRequest request ) {}