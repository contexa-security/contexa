package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OfficialVerificationOperatorSnapshotServiceTest {

    private static final String TENANT_ID = "tenant-001";
    private static final String PACKAGE_ID = "sealed-request-evidence-001";

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Test
    void replaceDiagnosticsForQualityTargetRejectsMissingTenantBeforeMutation() {
        OfficialVerificationOperatorSnapshotService service =
                new OfficialVerificationOperatorSnapshotService(jdbcTemplate, new ObjectMapper());

        assertThatIllegalArgumentException()
                .isThrownBy(() -> service.replaceDiagnosticsForQualityTarget(
                        " ",
                        PACKAGE_ID,
                        "resource-001",
                        "/resource/001",
                        "GET"))
                .withMessageContaining("tenantId");

        verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void replaceDiagnosticsForQualityTargetPreservesAllExistingOfficialRunHistory() {
        OfficialVerificationOperatorSnapshotService service =
                new OfficialVerificationOperatorSnapshotService(jdbcTemplate, new ObjectMapper());

        assertThat(service.replaceDiagnosticsForQualityTarget(
                TENANT_ID,
                PACKAGE_ID,
                "resource-001",
                "/resource/001",
                "GET"))
                .isEmpty();

        verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void recordTransactionIsAppliedAtTheSpringManagedPublicBoundary() {
        Method publicRecord = Arrays.stream(OfficialVerificationOperatorSnapshotService.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("record"))
                .findFirst()
                .orElseThrow();
        Method internalRecord = Arrays.stream(OfficialVerificationSnapshotRecordingService.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("record"))
                .findFirst()
                .orElseThrow();

        Transactional transactional = publicRecord.getAnnotation(Transactional.class);
        assertThat(transactional).isNotNull();
        assertThat(transactional.transactionManager()).isEqualTo("contexaTransactionManager");
        assertThat(transactional.propagation()).isEqualTo(Propagation.REQUIRED);
        assertThat(internalRecord.getAnnotation(Transactional.class)).isNull();
    }

    @Test
    void publishedSnapshotQueryRejectsIncompleteOrFailedExecution() {
        OfficialVerificationSnapshotRepository batchRepository = mock(OfficialVerificationSnapshotRepository.class);
        OfficialVerificationSnapshotReadModel readModel = mock(OfficialVerificationSnapshotReadModel.class);
        OfficialVerificationSnapshotAssembler assembler = mock(OfficialVerificationSnapshotAssembler.class);
        OfficialVerificationSnapshotCompletionRepository completion =
                mock(OfficialVerificationSnapshotCompletionRepository.class);
        OfficialVerificationSnapshotIntegrityRepositories integrity =
                new OfficialVerificationSnapshotIntegrityRepositories(
                        completion,
                        mock(OfficialVerificationSnapshotRelationIntegrityRepository.class),
                        mock(OfficialVerificationCustomerPurposeIntegrityRepository.class),
                        mock(OfficialVerificationCustomerDisplayIntegrityRepository.class),
                        mock(OfficialVerificationContractLinkIntegrityRepository.class));
        OfficialVerificationSnapshotQueryService queryService = new OfficialVerificationSnapshotQueryService(
                batchRepository, readModel, assembler, "catalog-v1", integrity);
        OfficialVerificationOperatorSnapshotService.OperatorRunBatch batch =
                mock(OfficialVerificationOperatorSnapshotService.OperatorRunBatch.class);
        when(batch.aggregateRunId()).thenReturn("agg-failed");
        when(batchRepository.findCurrentBatch("pkg-001", "agg-failed", "catalog-v1"))
                .thenReturn(Optional.of(batch));
        when(completion.publishableSnapshotExists("agg-failed")).thenReturn(false);

        assertThat(queryService.findPublished("pkg-001", "agg-failed").available()).isFalse();
        verify(completion).publishableSnapshotExists("agg-failed");
        verifyNoInteractions(readModel, assembler);
    }
}
