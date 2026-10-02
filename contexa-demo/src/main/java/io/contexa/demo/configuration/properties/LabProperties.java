package io.contexa.demo.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("lab")
public record LabProperties(
        String role,
        String accountPassword,
        LabEndpoints endpoints,
        ModelSelection chat,
        ModelSelection embedding
) {

}
