package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.Locale;

public record OfficialVerificationSubject(
        String tenantId,
        String resourceUrl,
        String resourceId,
        String httpMethod) {

    public OfficialVerificationSubject {
        tenantId = value(tenantId);
        resourceUrl = value(resourceUrl);
        resourceId = value(resourceId);
        httpMethod = value(httpMethod).toUpperCase(Locale.ROOT);
    }

    public boolean matches(RuntimeEvidenceVerificationRun run) {
        return run != null
                && tenantId.equals(value(run.tenantId()))
                && resourceUrl.equals(value(run.resourceUrl()))
                && resourceId.equals(value(run.resourceId()))
                && httpMethod.equals(value(run.httpMethod()).toUpperCase(Locale.ROOT));
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }
}
