package io.contexa.contexaiam.security.xacml.pip.context;

/**
 * 자원(Resource)의 상세 정보를 담는 객체.
 */
public record ResourceDetails(
        String type,       // 예: "URL", "METHOD"
        String identifier  /* 예: "/admin/**", "com.example.Service.method" */) {}
