package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IAM-D28: a package sealed without a tenant belongs to the deployment default tenant. Its official verification runs
 * under that tenant, so its execution status is read under that tenant too, not dropped as tenantless.
 */
class OfficialVerificationExecutionLedgerTenantTest {

    private final OfficialVerificationExecutionLockService locks = mock(OfficialVerificationExecutionLockService.class);
    private final OfficialVerificationEvidencePreflight preflight = mock(OfficialVerificationEvidencePreflight.class);
    private final OfficialVerificationExecutionLedger ledger = new OfficialVerificationExecutionLedger(locks,
            mock(OfficialVerificationOperatorSnapshotService.class), mock(OfficialVerificationMetricContract.class),
            preflight, new ObjectMapper(), mock(PromptQualityMessageResolver.class));

    @Test
    void theStatusOfAPackageWithoutATenantIsReadUnderTheDefaultTenant() {
        SealedEvidencePackage tenantless = SealedEvidencePackage.builder().packageId("pkg-1").tenantId("").build();
        when(preflight.findByPackageId("pkg-1")).thenReturn(Optional.of(tenantless));
        OfficialVerificationExecutionStatus latest = OfficialVerificationExecutionStatus.empty("pkg-1");
        OfficialVerificationExecutionStatus ofRun = OfficialVerificationExecutionStatus.empty("pkg-1");
        when(locks.status(SealedEvidencePackage.DEFAULT_TENANT_ID, "pkg-1")).thenReturn(latest);
        when(locks.status(SealedEvidencePackage.DEFAULT_TENANT_ID, "pkg-1", "run-1")).thenReturn(ofRun);

        assertThat(ledger.status("pkg-1")).isSameAs(latest);
        assertThat(ledger.status("pkg-1", "run-1")).isSameAs(ofRun);
    }

    @Test
    void aPackageWithItsOwnTenantKeepsIt() {
        SealedEvidencePackage owned = SealedEvidencePackage.builder().packageId("pkg-2").tenantId("tenant-a").build();
        when(preflight.findByPackageId("pkg-2")).thenReturn(Optional.of(owned));
        OfficialVerificationExecutionStatus latest = OfficialVerificationExecutionStatus.empty("pkg-2");
        when(locks.status("tenant-a", "pkg-2")).thenReturn(latest);

        assertThat(ledger.status("pkg-2")).isSameAs(latest);
    }
}
