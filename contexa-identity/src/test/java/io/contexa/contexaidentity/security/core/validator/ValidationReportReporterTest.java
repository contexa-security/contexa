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
package io.contexa.contexaidentity.security.core.validator;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ValidationReportReporterTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(ValidationReportReporter.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(logged);
    }

    @Test
    @DisplayName("A report of warnings alone is a warning: the application starts")
    void aReportOfWarningsAloneIsAWarning() {
        ValidationResult result = new ValidationResult();
        result.addWarning("rpName is not set");

        ValidationReportReporter.reportAndThrowOnError(result, "dsl");

        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getFormattedMessage()).contains("rpName is not set");
        });
    }

    @Test
    @DisplayName("A report with errors stays an error and stops the start")
    void aReportWithErrorsStaysAnError() {
        ValidationResult result = new ValidationResult();
        result.addError("rpId is not set");

        assertThatThrownBy(() -> ValidationReportReporter.reportAndThrowOnError(result, "dsl"))
                .isInstanceOf(DslConfigurationException.class);

        assertThat(logged.list).singleElement().satisfies(event -> assertThat(event.getLevel()).isEqualTo(Level.ERROR));
    }
}
