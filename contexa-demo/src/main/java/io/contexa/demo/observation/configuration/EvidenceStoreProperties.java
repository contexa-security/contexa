package io.contexa.demo.observation.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("lab.evidence")
public record EvidenceStoreProperties(
        String baselineUrl,
        String contexaUrl,
        String securityUrl,
        String username,
        String password) {
}
