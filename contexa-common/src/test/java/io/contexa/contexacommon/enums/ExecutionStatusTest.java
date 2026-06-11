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
package io.contexa.contexacommon.enums;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class ExecutionStatusTest {

    @Test
    @DisplayName("Enum has exactly 8 values")
    void enum_shouldHaveExactly8Values() {
        assertThat(ExecutionStatus.values()).hasSize(8);
    }

    @Test
    @DisplayName("PENDING is not completed")
    void pending_shouldNotBeCompleted() {
        assertThat(ExecutionStatus.PENDING.isCompleted()).isFalse();
    }

    @Test
    @DisplayName("PROCESSING is not completed")
    void processing_shouldNotBeCompleted() {
        assertThat(ExecutionStatus.PROCESSING.isCompleted()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = ExecutionStatus.class, names = {"SUCCESS", "COMPLETED", "PARTIAL_SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"})
    @DisplayName("Terminal statuses are completed")
    void terminalStatuses_shouldBeCompleted(ExecutionStatus status) {
        assertThat(status.isCompleted()).isTrue();
    }

    @Test
    @DisplayName("SUCCESS is successful")
    void success_shouldBeSuccessful() {
        assertThat(ExecutionStatus.SUCCESS.isSuccessful()).isTrue();
    }

    @Test
    @DisplayName("PARTIAL_SUCCESS is successful")
    void partialSuccess_shouldBeSuccessful() {
        assertThat(ExecutionStatus.PARTIAL_SUCCESS.isSuccessful()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = ExecutionStatus.class, names = {"PENDING", "PROCESSING", "COMPLETED", "FAILED", "TIMEOUT", "CANCELLED"})
    @DisplayName("Non-success statuses are not successful")
    void nonSuccessStatuses_shouldNotBeSuccessful(ExecutionStatus status) {
        assertThat(status.isSuccessful()).isFalse();
    }

    @Test
    @DisplayName("FAILED is completed but not successful")
    void failed_shouldBeCompletedButNotSuccessful() {
        assertThat(ExecutionStatus.FAILED.isCompleted()).isTrue();
        assertThat(ExecutionStatus.FAILED.isSuccessful()).isFalse();
    }

    @Test
    @DisplayName("TIMEOUT is completed but not successful")
    void timeout_shouldBeCompletedButNotSuccessful() {
        assertThat(ExecutionStatus.TIMEOUT.isCompleted()).isTrue();
        assertThat(ExecutionStatus.TIMEOUT.isSuccessful()).isFalse();
    }

    @Test
    @DisplayName("CANCELLED is completed but not successful")
    void cancelled_shouldBeCompletedButNotSuccessful() {
        assertThat(ExecutionStatus.CANCELLED.isCompleted()).isTrue();
        assertThat(ExecutionStatus.CANCELLED.isSuccessful()).isFalse();
    }

    @Test
    @DisplayName("Each status has displayName and description")
    void eachStatus_shouldHaveDisplayNameAndDescription() {
        for (ExecutionStatus status : ExecutionStatus.values()) {
            assertThat(status.getDisplayName()).isNotNull().isNotEmpty();
            assertThat(status.getDescription()).isNotNull().isNotEmpty();
        }
    }

    @Test
    @DisplayName("PENDING has correct display values")
    void pending_shouldHaveCorrectDisplayValues() {
        assertThat(ExecutionStatus.PENDING.getDisplayName()).isEqualTo("Pending");
        assertThat(ExecutionStatus.PENDING.getDescription()).isEqualTo("Request is pending");
    }

    @Test
    @DisplayName("PROCESSING has correct display values")
    void processing_shouldHaveCorrectDisplayValues() {
        assertThat(ExecutionStatus.PROCESSING.getDisplayName()).isEqualTo("Processing");
        assertThat(ExecutionStatus.PROCESSING.getDescription()).isEqualTo("Request is being processed");
    }
}
