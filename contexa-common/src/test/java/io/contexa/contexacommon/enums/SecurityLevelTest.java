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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SecurityLevelTest {

    @Nested
    @DisplayName("Level values")
    class LevelValueTest {

        @ParameterizedTest
        @CsvSource({
                "MINIMAL, 1",
                "STANDARD, 2",
                "ENHANCED, 3",
                "HIGH, 4",
                "MAXIMUM, 5"
        })
        @DisplayName("Should return correct level integer value")
        void shouldReturnCorrectLevelValue(SecurityLevel level, int expectedValue) {
            assertThat(level.getLevel()).isEqualTo(expectedValue);
        }
    }

    @Nested
    @DisplayName("meetsRequirement")
    class MeetsRequirementTest {

        @Test
        @DisplayName("Should return true when level equals required level")
        void shouldReturnTrueForSameLevel() {
            assertThat(SecurityLevel.STANDARD.meetsRequirement(SecurityLevel.STANDARD)).isTrue();
        }

        @Test
        @DisplayName("Should return true when level exceeds required level")
        void shouldReturnTrueForHigherLevel() {
            assertThat(SecurityLevel.HIGH.meetsRequirement(SecurityLevel.STANDARD)).isTrue();
        }

        @Test
        @DisplayName("Should return false when level is below required level")
        void shouldReturnFalseForLowerLevel() {
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.STANDARD)).isFalse();
        }

        @Test
        @DisplayName("MAXIMUM should meet all security levels")
        void maximumShouldMeetAllLevels() {
            for (SecurityLevel required : SecurityLevel.values()) {
                assertThat(SecurityLevel.MAXIMUM.meetsRequirement(required)).isTrue();
            }
        }

        @Test
        @DisplayName("MINIMAL should not meet STANDARD requirement")
        void minimalShouldNotMeetStandard() {
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.STANDARD)).isFalse();
        }

        @Test
        @DisplayName("MINIMAL should only meet MINIMAL requirement")
        void minimalShouldOnlyMeetMinimal() {
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.MINIMAL)).isTrue();
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.STANDARD)).isFalse();
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.ENHANCED)).isFalse();
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.HIGH)).isFalse();
            assertThat(SecurityLevel.MINIMAL.meetsRequirement(SecurityLevel.MAXIMUM)).isFalse();
        }

        @Test
        @DisplayName("ENHANCED should meet MINIMAL, STANDARD, and ENHANCED")
        void enhancedShouldMeetUpToEnhanced() {
            assertThat(SecurityLevel.ENHANCED.meetsRequirement(SecurityLevel.MINIMAL)).isTrue();
            assertThat(SecurityLevel.ENHANCED.meetsRequirement(SecurityLevel.STANDARD)).isTrue();
            assertThat(SecurityLevel.ENHANCED.meetsRequirement(SecurityLevel.ENHANCED)).isTrue();
            assertThat(SecurityLevel.ENHANCED.meetsRequirement(SecurityLevel.HIGH)).isFalse();
            assertThat(SecurityLevel.ENHANCED.meetsRequirement(SecurityLevel.MAXIMUM)).isFalse();
        }
    }

    @Nested
    @DisplayName("Display properties")
    class DisplayPropertiesTest {

        @ParameterizedTest
        @EnumSource(SecurityLevel.class)
        @DisplayName("Should have non-empty displayName for all levels")
        void shouldHaveNonEmptyDisplayName(SecurityLevel level) {
            assertThat(level.getDisplayName()).isNotNull().isNotBlank();
        }

        @ParameterizedTest
        @EnumSource(SecurityLevel.class)
        @DisplayName("Should have non-empty description for all levels")
        void shouldHaveNonEmptyDescription(SecurityLevel level) {
            assertThat(level.getDescription()).isNotNull().isNotBlank();
        }

        @Test
        @DisplayName("Should return expected displayName for MINIMAL")
        void shouldReturnExpectedDisplayNameForMinimal() {
            assertThat(SecurityLevel.MINIMAL.getDisplayName()).isEqualTo("Minimal Security");
        }

        @Test
        @DisplayName("Should return expected displayName for MAXIMUM")
        void shouldReturnExpectedDisplayNameForMaximum() {
            assertThat(SecurityLevel.MAXIMUM.getDisplayName()).isEqualTo("Maximum Security");
        }
    }
}
