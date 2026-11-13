package io.contexa.autoconfigure.core.llm;

import io.contexa.contexacore.std.llm.gate.ModelCallScope;
import org.junit.jupiter.api.Test;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.web.client.ResourceAccessException;

import java.net.ConnectException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * IAM-D62: the RetryTemplate beans the model clients take (spring.ai.retry) get the listener that ends the retry of a
 * Contexa model call to an unreachable server; their settings are not changed.
 */
class ModelCallRetryListenerRegistrarTest {

    @Test
    void aRetryTemplateBeanStopsAContexaCallToAnUnreachableServerAtOnce() {
        RetryTemplate template = RetryTemplate.builder().maxAttempts(5).retryOn(ResourceAccessException.class)
                .fixedBackoff(1).build();
        Object processed = new ModelCallRetryListenerRegistrar().postProcessAfterInitialization(template, "retryTemplate");
        AtomicInteger attempts = new AtomicInteger();

        assertThat(processed).isSameAs(template);
        assertThatThrownBy(() -> ModelCallScope.call(() -> template.execute(context -> {
            attempts.incrementAndGet();
            throw new ResourceAccessException("I/O error on POST", new ConnectException("Connection refused"));
        }))).isInstanceOf(ResourceAccessException.class);
        assertThat(attempts).hasValue(1);
    }

    @Test
    void anyOtherBeanIsLeftAsItIs() {
        Object bean = new Object();

        assertThat(new ModelCallRetryListenerRegistrar().postProcessAfterInitialization(bean, "other")).isSameAs(bean);
    }
}
