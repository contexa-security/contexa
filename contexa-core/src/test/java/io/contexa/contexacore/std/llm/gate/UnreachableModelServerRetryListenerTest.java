package io.contexa.contexacore.std.llm.gate;

import org.junit.jupiter.api.Test;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.web.client.ResourceAccessException;

import java.net.ConnectException;
import java.net.SocketException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * IAM-D62: a model call of Contexa whose server cannot be reached is tried once by the model client's retry; the
 * application's own calls, and a failure after the server was reached, keep the configured retry.
 */
class UnreachableModelServerRetryListenerTest {

    private final RetryTemplate retry = RetryTemplate.builder()
            .maxAttempts(4)
            .retryOn(ResourceAccessException.class)
            .fixedBackoff(1)
            .withListener(new UnreachableModelServerRetryListener())
            .build();

    @Test
    void aContexaCallToAnUnreachableServerIsTriedOnce() {
        AtomicInteger attempts = new AtomicInteger();

        assertThatThrownBy(() -> ModelCallScope.call(() -> retry.execute(context -> {
            attempts.incrementAndGet();
            throw new ResourceAccessException("I/O error on POST", new ConnectException("Connection refused"));
        }))).isInstanceOf(ResourceAccessException.class);

        assertThat(attempts).hasValue(1);
        assertThat(ModelCallScope.active()).isFalse();
    }

    @Test
    void theApplicationsOwnCallKeepsItsRetry() {
        AtomicInteger attempts = new AtomicInteger();

        assertThatThrownBy(() -> retry.execute(context -> {
            attempts.incrementAndGet();
            throw new ResourceAccessException("I/O error on POST", new ConnectException("Connection refused"));
        })).isInstanceOf(ResourceAccessException.class);

        assertThat(attempts).hasValue(4);
    }

    @Test
    void aFailureAfterTheServerWasReachedKeepsItsRetry() {
        AtomicInteger attempts = new AtomicInteger();

        assertThatThrownBy(() -> ModelCallScope.call(() -> retry.execute(context -> {
            attempts.incrementAndGet();
            throw new ResourceAccessException("I/O error on POST", new SocketException("Connection reset"));
        }))).isInstanceOf(ResourceAccessException.class);

        assertThat(attempts).hasValue(4);
    }
}
