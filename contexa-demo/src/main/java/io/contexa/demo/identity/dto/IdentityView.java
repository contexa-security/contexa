package io.contexa.demo.identity.dto;

import java.util.List;

public record IdentityView(
        String role,
        boolean authenticated,
        String username,
        List<String> authorities,
        List<String> accountAuthorities,
        boolean sessionPresent,
        String authenticationType,
        String loginUrl,
        String portalUrl,
        String baselineUrl,
        String contexaUrl,
        String staticPolicySha256,
        AuthenticationProgress authenticationProgress
) {

}
