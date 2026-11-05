/* Copyright 2026 The Contexa Project */
package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-10: a protected method that ran with no user leaves a row a reader can find, and a job that runs every second does not
 * write a row every second into a table it does not own.
 */
class ProtectableLlmSuppressionWriterWithoutUserTest {

    private final JdbcOperations jdbc = mock(JdbcOperations.class);
    private final AtomicLong now = new AtomicLong(1_000L);
    private final ProtectableLlmSuppressionWriter writer =
            new ProtectableLlmSuppressionWriter(() -> jdbc, new ObjectMapper(), null, now::get);
    private final MethodInvocation invocation = mock(MethodInvocation.class);

    @BeforeEach
    void setUp() throws Exception {
        Method method = Job.class.getMethod("run");
        when(invocation.getMethod()).thenReturn(method);
    }

    private Object[] writtenRow() {
        ArgumentCaptor<Object[]> row = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).update(anyString(), row.capture());
        return row.getValue();
    }

    @Test
    void theRowSaysWhichMethodRanAndThatItHadNoUser() {
        writer.recordRanWithoutUser(invocation, "ENFORCE");

        Object[] row = writtenRow();
        assertThat(row[5]).as("user_id").isNull();
        assertThat(row[10]).as("suppression_reason").isEqualTo(ProtectableLlmSuppressionWriter.RAN_WITHOUT_USER);
        assertThat(row[15]).as("resource_id").isEqualTo("Job.run");
        assertThat(row[16].toString()).contains("\"callsSinceLastRecord\":1", "\"zeroTrustMode\":\"ENFORCE\"");
    }

    @Test
    void callsCloseTogetherShareOneRow() {
        writer.recordRanWithoutUser(invocation, "ENFORCE");
        writer.recordRanWithoutUser(invocation, "ENFORCE");
        writer.recordRanWithoutUser(invocation, "ENFORCE");

        verify(jdbc, times(1)).update(anyString(), any(Object[].class));
    }

    @Test
    void theNextRowCountsTheCallsSinceTheLastOne() {
        writer.recordRanWithoutUser(invocation, "ENFORCE");
        writer.recordRanWithoutUser(invocation, "ENFORCE");
        writer.recordRanWithoutUser(invocation, "ENFORCE");
        now.addAndGet(Duration.ofMinutes(1).toNanos());

        writer.recordRanWithoutUser(invocation, "ENFORCE");

        ArgumentCaptor<Object[]> rows = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc, times(2)).update(anyString(), rows.capture());
        assertThat(rows.getAllValues().get(1)[16].toString()).contains("\"callsSinceLastRecord\":3");
    }

    @Test
    void withoutADatabaseNothingIsWrittenAndNothingFails() {
        ProtectableLlmSuppressionWriter noDatabase =
                new ProtectableLlmSuppressionWriter(() -> null, new ObjectMapper(), null, now::get);

        noDatabase.recordRanWithoutUser(invocation, "ENFORCE");

        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }

    public static class Job {

        public void run() {
        }
    }
}
