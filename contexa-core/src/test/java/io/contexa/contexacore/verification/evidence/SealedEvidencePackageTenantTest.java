package io.contexa.contexacore.verification.evidence;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IAM-D28: a package belongs to its own tenant, or to the deployment default when it names none. Sealing writes the
 * default for an event without a tenant, and verification reads a package sealed earlier without one the same way.
 */
class SealedEvidencePackageTenantTest {

    @Test
    void aPackageWithoutATenantBelongsToTheDeploymentDefault() {
        assertThat(SealedEvidencePackage.tenantOrDefault(null)).isEqualTo(SealedEvidencePackage.DEFAULT_TENANT_ID);
        assertThat(SealedEvidencePackage.tenantOrDefault("")).isEqualTo("default");
        assertThat(SealedEvidencePackage.tenantOrDefault("  ")).isEqualTo("default");
        assertThat(SealedEvidencePackage.tenantOrDefault("tenant-a")).isEqualTo("tenant-a");
    }
}
