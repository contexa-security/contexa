/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.advisor.security;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacore.properties.ContexaAdvisorProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The audit line of a model call names the session by its reference; the id itself signs its owner in. */
class SecurityContextAdvisorSessionLogTest {

    private static final String LIVE_SESSION = "F7A9C31D0B2E4F6A8C1D3E5F7A9B0C2D";

    private final Logger logger = (Logger) LoggerFactory.getLogger(SecurityContextAdvisor.class);
    private final ListAppender<ILoggingEvent> lines = new ListAppender<>();
    private final SecurityContextAdvisor advisor = new SecurityContextAdvisor(null, new ContexaAdvisorProperties());

    @BeforeEach
    void listen() {
        lines.start();
        logger.addAppender(lines);
    }

    @AfterEach
    void stop() {
        logger.detachAppender(lines);
    }

    private String auditLineFor(Object sessionId) {
        Map<String, Object> context = new HashMap<>();
        context.put("user.id", "alice");
        context.put("session.id", sessionId);
        advisor.afterCall(null, ChatClientRequest.builder().prompt(new Prompt("hello")).context(context).build());
        return lines.list.get(lines.list.size() - 1).getFormattedMessage();
    }

    @Test
    void theAuditLineCarriesTheReferenceAndNotTheSession() {
        assertThat(auditLineFor(LIVE_SESSION)).doesNotContain(LIVE_SESSION)
                .contains(RequestFactRedaction.sessionReference(LIVE_SESSION));
    }

    @Test
    void aCallWithoutASessionStillWritesItsLine() {
        assertThat(auditLineFor(null)).contains("sessionId: null");
    }
}
