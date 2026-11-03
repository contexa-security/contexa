package io.contexa.contexaiam.admin.promptquality.evidence;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import org.mockito.ArgumentCaptor;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;

/**
 * R4-C3: a sealed evidence package is only ever inserted. A package that already has a row is refused whatever its seal
 * flag says, so no update statement is left to run.
 */
class JdbcSealedEvidencePackageRepositoryTest {

    @Test
    void aPackageThatAlreadyHasARowIsNeverUpdated() {
        JdbcOperations jdbc = mock(JdbcOperations.class);
        when(jdbc.update(anyString(), any(Object[].class))).thenReturn(1);
        JdbcSealedEvidencePackageRepository repository = new JdbcSealedEvidencePackageRepository(jdbc);
        SealedEvidencePackage stored = SealedEvidencePackage.builder()
                .id(7L)
                .packageId("pkg-7")
                .correlationId("req-7")
                .sealed(false)
                .build();

        assertThatThrownBy(() -> repository.save(stored))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be modified");
        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }

    /** docs/agent A5-6: a schema 3 package is linked after the latest linked package and stored with its signature. */
    @Test
    void aSchemaThreePackageIsLinkedAfterTheLatestOneAndStoredSigned() {
        JdbcOperations jdbc = mock(JdbcOperations.class);
        when(jdbc.queryForList(anyString(), eq(String.class), any(Object[].class))).thenReturn(List.of("earlier-hash"));
        when(jdbc.queryForObject(anyString(), eq(Long.class), any(Object[].class))).thenReturn(11L);
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                .encodeToString("k1-0123456789abcdef0123456789abcd".getBytes())), null);
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(signer);
        JdbcSealedEvidencePackageRepository repository = new JdbcSealedEvidencePackageRepository(jdbc);
        repository.setIntegrity(integrity);
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("pkg-11")
                .correlationId("req-11")
                .tenantId("tenant-a")
                .userId("alice")
                .capturedAt(Instant.parse("2026-10-24T05:00:00Z"))
                .schemaVersion(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION)
                .build();

        repository.save(pkg);

        assertThat(pkg.getPreviousPackageHash()).isEqualTo("earlier-hash");
        assertThat(integrity.evaluate(pkg)).isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
        ArgumentCaptor<Object[]> arguments = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).queryForObject(contains("insert into ctxa_sealed_evidence_package"), eq(Long.class), arguments.capture());
        assertThat(arguments.getValue()).hasSize(33).contains("earlier-hash", pkg.getPackageSignature(), "k1");
    }
}
