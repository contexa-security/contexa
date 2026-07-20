/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskExecutor;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

class IamWebSocketConfigurationTest {

    @Test
    void createsMessageBrokerExecutorsAndStats() {
        try (AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext()) {
            context.setServletContext(new MockServletContext());
            context.register(WebSocketConfig.class);
            context.refresh();

            assertThat(context.getBean("clientInboundChannelExecutor"))
                    .isInstanceOf(TaskExecutor.class);
            assertThat(context.getBean("clientOutboundChannelExecutor"))
                    .isInstanceOf(TaskExecutor.class);
            assertThat(context.containsBean("webSocketMessageBrokerStats")).isTrue();
        }
    }
}
