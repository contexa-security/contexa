package io.contexa.demo.identity.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties("lab.identity")
public record IdentityProperties(
        List<String> usernames,
        String baselineDbUrl
) {

}
