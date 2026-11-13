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

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.entity.ManagedResource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The handler of {@link GlobalExceptionHandler} answers an {@link IllegalArgumentException} with its text, with the
 * status 400. The services of the console refuse with such an exception on purpose, and its text is for the person who
 * asked. The JDK's lookup of an enum constant throws one too, and its text names the enum's class: a filter value that is
 * no constant of the resource status reached the answer as a message that began "No enum constant" and went on with
 * the class. It is told as an invalid parameter now, and the operators read the text in the log. The status and the
 * fields of the answer are as they were.
 */
class GlobalExceptionHandlerInternalMessageTest {

    /**
     * A filter of the resource status read with the JDK's lookup of the enum constant, as the resource screens read it.
     * The old workbench address that read it is a redirect to the policy center now (D03).
     */
    @RestController
    static class StatusFilter {

        @GetMapping("/status-filter")
        String filter(@RequestParam String status) {
            return ManagedResource.Status.valueOf(status).name();
        }
    }

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);

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
    @DisplayName("a status filter that is no constant of the status does not answer with the enum's class")
    void anEnumLookupDoesNotAnswerWithTheClass() throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new StatusFilter())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();

        MvcResult result = mvc.perform(get("/status-filter").param("status", "BOGUS"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.errorCode").value("INVALID_ARGUMENT"))
                .andExpect(jsonPath("$.message").value("Invalid request parameter"))
                .andReturn();

        assertThat(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .doesNotContain("No enum constant", "io.contexa");
    }

    @Test
    @DisplayName("the operators read the text of the lookup in the log")
    void theLogKeepsTheText() {
        IllegalArgumentException lookup = enumLookupFailure();

        new GlobalExceptionHandler().handleIllegalArgumentException(lookup);

        assertThat(logged.list).anySatisfy(event -> assertThat(event.getFormattedMessage())
                .contains(lookup.getMessage()));
    }

    @Test
    @DisplayName("what the services refuse with is still answered with its own text, with the status it had")
    void aRefusalKeepsItsText() {
        ResponseEntity<ErrorResponse> answer = new GlobalExceptionHandler()
                .handleIllegalArgumentException(new IllegalArgumentException("Group name already exists"));

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(answer.getBody().errorCode()).isEqualTo("INVALID_ARGUMENT");
        assertThat(answer.getBody().message()).isEqualTo("Group name already exists");
        assertThat(logged.list).isEmpty();
    }

    @Test
    @DisplayName("an illegal argument without a text is answered with the general words it always had")
    void noTextIsAnInvalidParameter() {
        ResponseEntity<ErrorResponse> answer = new GlobalExceptionHandler()
                .handleIllegalArgumentException(new IllegalArgumentException());

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(answer.getBody().message()).isEqualTo("Invalid request parameter");
    }

    private static IllegalArgumentException enumLookupFailure() {
        try {
            TimeUnit.valueOf("BOGUS");
        } catch (IllegalArgumentException e) {
            return e;
        }
        throw new AssertionError("the JDK took BOGUS for a time unit");
    }
}
