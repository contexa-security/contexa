package io.contexa.contexaiam.security.xacml.pip.context;

import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;

/**
 * 요청 환경(Environment)의 상세 정보를 담는 Record.
 */
public record EnvironmentDetails(
        String remoteIp,
        LocalDateTime timestamp,
        HttpServletRequest request /* 원본 요청 객체에 대한 참조를 유지하여 확장성 확보 */) {}