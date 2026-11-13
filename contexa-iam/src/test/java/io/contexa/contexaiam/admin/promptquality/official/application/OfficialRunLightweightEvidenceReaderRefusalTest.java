package io.contexa.contexaiam.admin.promptquality.official.application;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IAM-D13: a detail asked for a package that does not exist is a refusal, logged as a warning without a stack and
 * answered by the full lookup; a database that cannot answer stays an error with its stack.
 */
class OfficialRunLightweightEvidenceReaderRefusalTest {

    private final JdbcOperations jdbc = mock(JdbcOperations.class);
    private final PromptQualityRuntimeEvidenceService evidence = mock(PromptQualityRuntimeEvidenceService.class);
    private final OfficialRunLightweightEvidenceReader reader = new OfficialRunLightweightEvidenceReader(jdbc,
            new ObjectMapper(), mock(RuntimeEvidencePromptConsistencyGate.class), evidence,
            mock(SealedEvidencePackageQueryService.class), PromptQualityTestResolvers.koreanBundle());
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(OfficialRunLightweightEvidenceReader.class);

    @BeforeEach
    void listen() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    @Test
    void anUnknownPackageIsAWarningWithoutAStack() {
        RuntimeEvidencePackageDetail answered = mock(RuntimeEvidencePackageDetail.class);
        when(jdbc.queryForObject(anyString(), any(RowMapper.class), any(Object[].class)))
                .thenThrow(new EmptyResultDataAccessException(1));
        when(evidence.findDetail("missing")).thenReturn(answered);

        assertThat(reader.findDetail("missing")).isSameAs(answered);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    @Test
    void aDatabaseFaultStaysAnErrorWithItsStack() {
        RuntimeEvidencePackageDetail answered = mock(RuntimeEvidencePackageDetail.class);
        when(jdbc.queryForObject(anyString(), any(RowMapper.class), any(Object[].class)))
                .thenThrow(new DataAccessResourceFailureException("connection lost"));
        when(evidence.findDetail("pkg-1")).thenReturn(answered);

        assertThat(reader.findDetail("pkg-1")).isSameAs(answered);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getThrowableProxy()).isNotNull();
        });
    }
}
