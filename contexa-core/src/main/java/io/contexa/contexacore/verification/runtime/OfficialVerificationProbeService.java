package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacommon.annotation.Protectable;

public class OfficialVerificationProbeService {

    @Protectable(
            resourceId = "official.verification.normal.{resourceId}",
            resourceUrl = "/admin/api/enterprise/verification/runtime/probe/normal/{resourceId}",
            httpMethod = "GET",
            criticality = "standard")
    public ProbeResult accessNormal(String resourceId) {
        return new ProbeResult(resourceId, "normal", "Normal resource", "Normal protected resource access completed.");
    }

    @Protectable(
            resourceId = "official.verification.sensitive.{resourceId}",
            resourceUrl = "/admin/api/enterprise/verification/runtime/probe/sensitive/{resourceId}",
            httpMethod = "GET",
            criticality = "sensitive")
    public ProbeResult accessSensitive(String resourceId) {
        return new ProbeResult(resourceId, "sensitive", "Sensitive resource", "Sensitive protected resource access completed.");
    }

    @Protectable(
            resourceId = "official.verification.critical.{resourceId}",
            resourceUrl = "/admin/api/enterprise/verification/runtime/probe/critical/{resourceId}",
            httpMethod = "GET",
            criticality = "critical")
    public ProbeResult accessCritical(String resourceId) {
        return new ProbeResult(resourceId, "critical", "Critical resource", "Critical protected resource access completed.");
    }

    @Protectable(
            resourceId = "official.verification.delegated.{resourceId}",
            resourceUrl = "/admin/api/enterprise/verification/runtime/probe/delegated/{resourceId}",
            httpMethod = "GET",
            criticality = "delegated")
    public ProbeResult accessDelegated(String resourceId) {
        return new ProbeResult(resourceId, "delegated", "Delegated resource", "Delegated protected resource access completed.");
    }

    public record ProbeResult(
            String resourceId,
            String endpointKey,
            String endpointLabel,
            String message) {
    }
}

