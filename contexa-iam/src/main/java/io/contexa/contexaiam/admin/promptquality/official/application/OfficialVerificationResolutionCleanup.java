package io.contexa.contexaiam.admin.promptquality.official.application;

@FunctionalInterface
public interface OfficialVerificationResolutionCleanup {

    void deleteDiagnosticPackage(String tenantId, String packageId);

    static OfficialVerificationResolutionCleanup none() {
        return (tenantId, packageId) -> { };
    }
}
