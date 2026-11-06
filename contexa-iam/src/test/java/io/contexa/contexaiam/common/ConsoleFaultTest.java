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
package io.contexa.contexaiam.common;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorException;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConsoleFaultTest {

    private static final String SQL = "could not execute statement [ERROR: duplicate key value violates unique "
            + "constraint \"uk_ctxa_role_name\"] [insert into ctxa_role (role_name) values (?)]";

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(ConsoleFaultTest.class);

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
    @DisplayName("the general text is the sentence the console's API already answers a fault with")
    void theGeneralText() {
        assertThat(ConsoleFault.MESSAGE).isEqualTo("The action could not be completed. See the server log.");
    }

    @Test
    @DisplayName("what the services refuse with is told in its own words")
    void refusalsAreToldInTheirOwnWords() {
        assertThat(ConsoleFault.textOf(new IllegalArgumentException("Group name already exists"))).isEqualTo("Group name already exists");
        assertThat(ConsoleFault.textOf(new IllegalStateException("Already resolved: id=7"))).isEqualTo("Already resolved: id=7");
        assertThat(ConsoleFault.textOf(new LastAdministratorException("without an active administrator: alice")))
                .isEqualTo("without an active administrator: alice");
        assertThat(ConsoleFault.textOf(new NoSuchElementException("Agent a-1 is not known"))).isEqualTo("Agent a-1 is not known");
        assertThat(ConsoleFault.textOf(new PolicyConflictException("conflicts with Allow all", List.of())))
                .isEqualTo("conflicts with Allow all");
    }

    @Test
    @DisplayName("anything else is a fault: the text names nothing of it")
    void faultsAreToldInGeneralWords() {
        assertThat(ConsoleFault.textOf(new RuntimeException(SQL))).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(new DataIntegrityViolationException(SQL))).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(new AccessDeniedException("Access Denied"))).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(new Exception(SQL))).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(new StackOverflowError())).isEqualTo(ConsoleFault.MESSAGE);
    }

    @Test
    @DisplayName("a refusal that says nothing, and no exception at all, are told in general words")
    void aRefusalWithoutTextIsAFaultOfNoWords() {
        assertThat(ConsoleFault.textOf(new IllegalArgumentException())).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(new IllegalStateException("  "))).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(null)).isEqualTo(ConsoleFault.MESSAGE);
    }

    @Test
    @DisplayName("the JDK's failed lookup of an enum constant names the enum's class: it is no refusal, though it is an illegal argument")
    void anEnumLookupThatFailsIsNoRefusal() {
        IllegalArgumentException lookup = enumLookupFailure();

        assertThat(lookup.getMessage()).startsWith("No enum constant ");
        assertThat(ConsoleFault.isRefusal(lookup)).isFalse();
        assertThat(ConsoleFault.textOf(lookup)).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(ConsoleFault.textOf(lookup, logger, "validate a policy")).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(logged.list).hasSize(1);
        assertThat(logged.list.get(0).getThrowableProxy().getMessage()).startsWith("No enum constant ");
    }

    @Test
    @DisplayName("a refusal of the services that only mentions an enum lookup in its text is still a refusal")
    void aRefusalThatMentionsAnEnumLookupIsStillARefusal() {
        IllegalArgumentException refusal = new IllegalArgumentException("The status is not one of: A, B (No enum constant)");

        assertThat(ConsoleFault.isRefusal(refusal)).isTrue();
        assertThat(ConsoleFault.textOf(refusal)).isEqualTo(refusal.getMessage());
    }

    private static IllegalArgumentException enumLookupFailure() {
        try {
            TimeUnit.valueOf("BOGUS");
        } catch (IllegalArgumentException e) {
            return e;
        }
        throw new AssertionError("the JDK took BOGUS for a time unit");
    }

    @Test
    @DisplayName("a fault is logged with its stack by the caller that has no log of its own; a refusal is not")
    void aFaultIsLoggedAndARefusalIsNot() {
        RuntimeException fault = new RuntimeException(SQL);

        String told = ConsoleFault.textOf(fault, logger, "delete role 5");
        String refused = ConsoleFault.textOf(new IllegalStateException("Role is in use"), logger, "delete role 5");

        assertThat(told).isEqualTo(ConsoleFault.MESSAGE);
        assertThat(refused).isEqualTo("Role is in use");
        assertThat(logged.list).hasSize(1);
        ILoggingEvent event = logged.list.get(0);
        assertThat(event.getLevel()).isEqualTo(Level.ERROR);
        assertThat(event.getFormattedMessage()).isEqualTo("The console could not delete role 5");
        assertThat(event.getThrowableProxy().getMessage()).isEqualTo(SQL);
    }
}
