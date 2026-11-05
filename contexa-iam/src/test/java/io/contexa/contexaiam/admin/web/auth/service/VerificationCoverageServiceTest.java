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
package io.contexa.contexaiam.admin.web.auth.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.dao.DataAccessResourceFailureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Q-1: an operator sees who could not answer a CHALLENGE before a user meets it. */
class VerificationCoverageServiceTest {

    private final UserRepository users = mock(UserRepository.class);
    private final VerificationCoverageService service =
            new VerificationCoverageService(users, "Shadow.Contexa.Local", () -> true);
    private final Logger logger = (Logger) LoggerFactory.getLogger(VerificationCoverageService.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void listen() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(appender);
    }

    @Test
    @DisplayName("a made-up address reaches nobody, and an agent is asked no factor")
    void whoCounts() {
        when(users.countWithoutVerificationFactor(true, "%@shadow.contexa.local", "%@agents.invalid")).thenReturn(3L);

        assertThat(service.usersWithoutFactor()).isEqualTo(3L);
    }

    @Test
    @DisplayName("without a mail server no address reaches anybody")
    void withoutAMailServer() {
        VerificationCoverageService noMail = new VerificationCoverageService(users, "shadow.contexa.local", () -> false);

        noMail.usersWithoutFactor();

        verify(users).countWithoutVerificationFactor(false, "%@shadow.contexa.local", "%@agents.invalid");
    }

    @Test
    @DisplayName("the start tells the operator how many and what to do")
    void theStartTells() {
        when(users.countWithoutVerificationFactor(anyBoolean(), anyString(), anyString())).thenReturn(4L);

        service.onApplicationEvent(mock(ApplicationReadyEvent.class));

        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(appender.list.get(0).getFormattedMessage()).contains("4 users").contains("BridgeUserEmailProvider");
    }

    @Test
    @DisplayName("everyone covered: the start says nothing")
    void nothingToSay() {
        service.onApplicationEvent(mock(ApplicationReadyEvent.class));

        assertThat(appender.list).isEmpty();
    }

    @Test
    @DisplayName("a database that cannot be read at the start stops nothing")
    void aFailingDatabaseStopsNothing() {
        when(users.countWithoutVerificationFactor(anyBoolean(), anyString(), anyString()))
                .thenThrow(new DataAccessResourceFailureException("database down"));

        assertThatCode(() -> service.onApplicationEvent(mock(ApplicationReadyEvent.class))).doesNotThrowAnyException();
    }
}
