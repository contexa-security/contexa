package io.contexa.contexaiam.admin.promptquality.evidence;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
}
