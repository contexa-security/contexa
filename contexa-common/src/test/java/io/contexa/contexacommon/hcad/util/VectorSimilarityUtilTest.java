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
package io.contexa.contexacommon.hcad.util;

import static org.assertj.core.api.Assertions.assertThat;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VectorSimilarityUtilTest {

    @BeforeEach
    void setUp() {
        // Reset ND4J check so pure Java fallback is used in test environment
        VectorSimilarityUtil.resetND4JCheck();
    }

    @Nested
    @DisplayName("cosineSimilarity with double arrays")
    class DoubleArrayTest {

        @Test
        @DisplayName("Should return ~1.0 for identical vectors")
        void shouldReturnOneForIdenticalVectors() {
            double[] vec = {1.0, 2.0, 3.0, 4.0};
            double result = VectorSimilarityUtil.cosineSimilarity(vec, vec);
            assertThat(result).isCloseTo(1.0, Offset.offset(1e-6));
        }

        @Test
        @DisplayName("Should return ~0.5 for orthogonal vectors (normalized)")
        void shouldReturnHalfForOrthogonalVectors() {
            double[] vecA = {1.0, 0.0, 0.0, 0.0};
            double[] vecB = {0.0, 1.0, 0.0, 0.0};
            double result = VectorSimilarityUtil.cosineSimilarity(vecA, vecB);
            assertThat(result).isCloseTo(0.5, Offset.offset(1e-6));
        }

        @Test
        @DisplayName("Should return ~0.0 for opposite vectors (normalized)")
        void shouldReturnZeroForOppositeVectors() {
            double[] vecA = {1.0, 2.0, 3.0, 4.0};
            double[] vecB = {-1.0, -2.0, -3.0, -4.0};
            double result = VectorSimilarityUtil.cosineSimilarity(vecA, vecB);
            assertThat(result).isCloseTo(0.0, Offset.offset(1e-6));
        }

        @Test
        @DisplayName("Should return NaN for null first vector")
        void shouldReturnNaNForNullFirstVector() {
            double[] vec = {1.0, 2.0};
            assertThat(VectorSimilarityUtil.cosineSimilarity((double[]) null, vec)).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for null second vector")
        void shouldReturnNaNForNullSecondVector() {
            double[] vec = {1.0, 2.0};
            assertThat(VectorSimilarityUtil.cosineSimilarity(vec, (double[]) null)).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for both null vectors")
        void shouldReturnNaNForBothNullVectors() {
            assertThat(VectorSimilarityUtil.cosineSimilarity((double[]) null, (double[]) null)).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for empty arrays")
        void shouldReturnNaNForEmptyArrays() {
            assertThat(VectorSimilarityUtil.cosineSimilarity(new double[0], new double[0])).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for dimension mismatch")
        void shouldReturnNaNForDimensionMismatch() {
            double[] vecA = {1.0, 2.0, 3.0};
            double[] vecB = {1.0, 2.0};
            assertThat(VectorSimilarityUtil.cosineSimilarity(vecA, vecB)).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for zero vector (norm = 0)")
        void shouldReturnNaNForZeroVector() {
            double[] vecA = {0.0, 0.0, 0.0, 0.0};
            double[] vecB = {1.0, 2.0, 3.0, 4.0};
            assertThat(VectorSimilarityUtil.cosineSimilarity(vecA, vecB)).isNaN();
        }

        @Test
        @DisplayName("Should return result in [0.0, 1.0] range for arbitrary vectors")
        void shouldReturnNormalizedResult() {
            double[] vecA = {0.5, 0.3, 0.8, 0.1};
            double[] vecB = {0.2, 0.7, 0.4, 0.9};
            double result = VectorSimilarityUtil.cosineSimilarity(vecA, vecB);
            assertThat(result).isBetween(0.0, 1.0);
        }
    }

    @Nested
    @DisplayName("cosineSimilarity with float arrays")
    class FloatArrayTest {

        @Test
        @DisplayName("Should return ~1.0 for identical float vectors")
        void shouldReturnOneForIdenticalFloatVectors() {
            float[] vec = {1.0f, 2.0f, 3.0f, 4.0f};
            double result = VectorSimilarityUtil.cosineSimilarity(vec, vec);
            assertThat(result).isCloseTo(1.0, Offset.offset(1e-5));
        }

        @Test
        @DisplayName("Should return NaN for null float vectors")
        void shouldReturnNaNForNullFloatVectors() {
            assertThat(VectorSimilarityUtil.cosineSimilarity((float[]) null, (float[]) null)).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for empty float arrays")
        void shouldReturnNaNForEmptyFloatArrays() {
            assertThat(VectorSimilarityUtil.cosineSimilarity(new float[0], new float[0])).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for float dimension mismatch")
        void shouldReturnNaNForFloatDimensionMismatch() {
            float[] vecA = {1.0f, 2.0f, 3.0f};
            float[] vecB = {1.0f, 2.0f};
            assertThat(VectorSimilarityUtil.cosineSimilarity(vecA, vecB)).isNaN();
        }

        @Test
        @DisplayName("Should return NaN for zero float vector")
        void shouldReturnNaNForZeroFloatVector() {
            float[] vecA = {0.0f, 0.0f, 0.0f, 0.0f};
            float[] vecB = {1.0f, 2.0f, 3.0f, 4.0f};
            assertThat(VectorSimilarityUtil.cosineSimilarity(vecA, vecB)).isNaN();
        }

        @Test
        @DisplayName("Should return result in [0.0, 1.0] range for float vectors")
        void shouldReturnNormalizedFloatResult() {
            float[] vecA = {0.5f, 0.3f, 0.8f, 0.1f};
            float[] vecB = {0.2f, 0.7f, 0.4f, 0.9f};
            double result = VectorSimilarityUtil.cosineSimilarity(vecA, vecB);
            assertThat(result).isBetween(0.0, 1.0);
        }

        @Test
        @DisplayName("Should return ~0.0 for opposite float vectors")
        void shouldReturnZeroForOppositeFloatVectors() {
            float[] vecA = {1.0f, 2.0f, 3.0f, 4.0f};
            float[] vecB = {-1.0f, -2.0f, -3.0f, -4.0f};
            double result = VectorSimilarityUtil.cosineSimilarity(vecA, vecB);
            assertThat(result).isCloseTo(0.0, Offset.offset(1e-5));
        }
    }
}
