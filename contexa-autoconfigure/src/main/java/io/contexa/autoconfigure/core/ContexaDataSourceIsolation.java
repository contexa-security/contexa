package io.contexa.autoconfigure.core;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.util.StringUtils;

final class ContexaDataSourceIsolation {

    private ContexaDataSourceIsolation() {
    }

    static void validate(ContexaDataSourceProperties properties, Environment environment) {
        String contexaUrl = normalize(properties.getUrl());
        if (!StringUtils.hasText(contexaUrl)) {
            throw new IllegalStateException("contexa.datasource.url must be configured for @EnableAISecurity. "
                    + "Use a dedicated Contexa database by default; sharing the application database requires explicit POC approval.");
        }

        String applicationUrl = normalize(environment.getProperty("spring.datasource.url"));
        if (!StringUtils.hasText(applicationUrl) || !contexaUrl.equals(applicationUrl)) {
            return;
        }

        ContexaDataSourceProperties.Isolation isolation = properties.getIsolation();
        if (isolation.isContexaOwnedApplication()) {
            return;
        }

        boolean sharedApproved = isolation.isAllowSharedApplicationDatasource()
                && isolation.isSharedApplicationDatasourceRiskAccepted();
        if (isProduction(environment)) {
            throw new IllegalStateException("contexa.datasource must not share the application datasource in production profiles");
        }
        if (!sharedApproved) {
            throw new IllegalStateException("contexa.datasource must not share spring.datasource unless "
                    + "contexa.datasource.isolation.allow-shared-application-datasource=true and "
                    + "contexa.datasource.isolation.shared-application-datasource-risk-accepted=true are both set for an approved POC");
        }
    }

    private static boolean isProduction(Environment environment) {
        return environment.acceptsProfiles(Profiles.of("prod", "production"));
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
