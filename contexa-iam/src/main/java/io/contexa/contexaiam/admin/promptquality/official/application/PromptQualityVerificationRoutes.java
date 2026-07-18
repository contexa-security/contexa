package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

final class PromptQualityVerificationRoutes {

    private PromptQualityVerificationRoutes() {
    }

    static String resourceDetail(PromptQualityProcessScope scope) {
        return "/contexa/admin/prompt-quality/resources/detail"
                + "?resourceUrl=" + encode(scope.resourceUrl())
                + "&resourceId=" + encode(scope.resourceId())
                + "&httpMethod=" + encode(scope.httpMethod());
    }

    static String runtimeEvidence(String packageId, PromptQualityProcessScope scope) {
        StringBuilder route = new StringBuilder("/contexa/admin/prompt-quality/runtime-evidence?");
        append(route, "packageId", packageId);
        appendScope(route, scope);
        return finish(route);
    }

    static String readiness(String packageId, PromptQualityProcessScope scope, String aggregateRunId) {
        StringBuilder route = new StringBuilder("/contexa/admin/prompt-quality/verification/readiness?");
        append(route, "packageId", packageId);
        append(route, "aggregateRunId", aggregateRunId);
        appendScope(route, scope);
        return finish(route);
    }

    static String metrics(String packageId, PromptQualityProcessScope scope, String aggregateRunId) {
        StringBuilder route = new StringBuilder("/contexa/admin/prompt-quality/verification/metrics?");
        append(route, "packageId", packageId);
        append(route, "aggregateRunId", aggregateRunId);
        appendScope(route, scope);
        return finish(route);
    }

    private static void appendScope(StringBuilder route, PromptQualityProcessScope scope) {
        if (scope == null) {
            return;
        }
        append(route, "resourceUrl", scope.resourceUrl());
        append(route, "resourceId", scope.resourceId());
        append(route, "httpMethod", scope.httpMethod());
    }

    private static void append(StringBuilder route, String name, String value) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        if (route.charAt(route.length() - 1) != '?') {
            route.append('&');
        }
        route.append(name).append('=').append(encode(value));
    }

    private static String finish(StringBuilder route) {
        return route.charAt(route.length() - 1) == '?'
                ? route.substring(0, route.length() - 1)
                : route.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}