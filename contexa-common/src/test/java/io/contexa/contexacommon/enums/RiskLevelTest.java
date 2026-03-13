package io.contexa.contexacommon.enums;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class RiskLevelTest {

    @Nested
    @DisplayName("fromScore boundary values")
    class FromScoreTest {

        @Test
        @DisplayName("Should return LOW for negative score")
        void shouldReturnLowForNegativeScore() {
            assertThat(RiskLevel.fromScore(-0.1)).isEqualTo(RiskLevel.LOW);
        }

        @Test
        @DisplayName("Should return LOW for score 0.0 (inclusive lower bound)")
        void shouldReturnLowForZero() {
            assertThat(RiskLevel.fromScore(0.0)).isEqualTo(RiskLevel.LOW);
        }

        @Test
        @DisplayName("Should return LOW for score just below 0.3")
        void shouldReturnLowForJustBelow03() {
            assertThat(RiskLevel.fromScore(0.29999)).isEqualTo(RiskLevel.LOW);
        }

        @Test
        @DisplayName("Should return MEDIUM for score 0.3 (boundary)")
        void shouldReturnMediumForExactly03() {
            assertThat(RiskLevel.fromScore(0.3)).isEqualTo(RiskLevel.MEDIUM);
        }

        @Test
        @DisplayName("Should return MEDIUM for score just below 0.6")
        void shouldReturnMediumForJustBelow06() {
            assertThat(RiskLevel.fromScore(0.59999)).isEqualTo(RiskLevel.MEDIUM);
        }

        @Test
        @DisplayName("Should return HIGH for score 0.6 (boundary)")
        void shouldReturnHighForExactly06() {
            assertThat(RiskLevel.fromScore(0.6)).isEqualTo(RiskLevel.HIGH);
        }

        @Test
        @DisplayName("Should return HIGH for score just below 0.8")
        void shouldReturnHighForJustBelow08() {
            assertThat(RiskLevel.fromScore(0.79999)).isEqualTo(RiskLevel.HIGH);
        }

        @Test
        @DisplayName("Should return CRITICAL for score 0.8 (boundary)")
        void shouldReturnCriticalForExactly08() {
            assertThat(RiskLevel.fromScore(0.8)).isEqualTo(RiskLevel.CRITICAL);
        }

        @Test
        @DisplayName("Should return CRITICAL for score just below 1.0")
        void shouldReturnCriticalForJustBelow10() {
            assertThat(RiskLevel.fromScore(0.99999)).isEqualTo(RiskLevel.CRITICAL);
        }

        @Test
        @DisplayName("Should return CRITICAL for score 1.0 (inclusive upper bound)")
        void shouldReturnCriticalForExactly10() {
            assertThat(RiskLevel.fromScore(1.0)).isEqualTo(RiskLevel.CRITICAL);
        }
    }

    @Nested
    @DisplayName("Score range properties")
    class ScoreRangeTest {

        @ParameterizedTest
        @CsvSource({
                "LOW, 0.0, 0.3",
                "MEDIUM, 0.3, 0.6",
                "HIGH, 0.6, 0.8",
                "CRITICAL, 0.8, 1.0"
        })
        @DisplayName("Should have correct min and max score for each level")
        void shouldHaveCorrectScoreRange(RiskLevel level, double expectedMin, double expectedMax) {
            assertThat(level.getMinScore()).isEqualTo(expectedMin);
            assertThat(level.getMaxScore()).isEqualTo(expectedMax);
        }
    }
}
