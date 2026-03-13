package io.contexa.contexacommon.hcad.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class HCADContextTest {

    private HCADContext createMinimalContext() {
        return HCADContext.builder()
                .userId("user-001")
                .sessionId("session-001")
                .requestPath("/api/test")
                .httpMethod("GET")
                .remoteIp("192.168.1.1")
                .userAgent("TestAgent/1.0")
                .timestamp(Instant.parse("2025-01-15T10:30:00Z"))
                .currentTrustScore(0.8)
                .recentRequestCount(10)
                .isNewSession(false)
                .isNewDevice(false)
                .isNewUser(false)
                .build();
    }

    @Nested
    @DisplayName("toVector")
    class ToVectorTest {

        @Test
        @DisplayName("Should return double array of size 384")
        void shouldReturnArrayOfSize384() {
            HCADContext ctx = createMinimalContext();
            double[] vector = ctx.toVector();
            assertThat(vector).hasSize(384);
        }

        @Test
        @DisplayName("Should contain values within reasonable range")
        void shouldContainValuesInReasonableRange() {
            HCADContext ctx = createMinimalContext();
            double[] vector = ctx.toVector();
            for (double v : vector) {
                assertThat(v).isBetween(-2.0, 2.0);
            }
        }

        @Test
        @DisplayName("Should produce different vectors for different HTTP methods")
        void shouldProduceDifferentVectorsForDifferentMethods() {
            HCADContext getCtx = createMinimalContext();
            HCADContext postCtx = HCADContext.builder()
                    .userId("user-001")
                    .sessionId("session-001")
                    .requestPath("/api/test")
                    .httpMethod("POST")
                    .remoteIp("192.168.1.1")
                    .timestamp(Instant.parse("2025-01-15T10:30:00Z"))
                    .currentTrustScore(0.8)
                    .recentRequestCount(10)
                    .isNewSession(false)
                    .isNewDevice(false)
                    .isNewUser(false)
                    .build();

            double[] getVector = getCtx.toVector();
            double[] postVector = postCtx.toVector();
            assertThat(getVector).isNotEqualTo(postVector);
        }
    }

    @Nested
    @DisplayName("toJson")
    class ToJsonTest {

        @Test
        @DisplayName("Should return parseable JSON string")
        void shouldReturnParseableJson() throws Exception {
            HCADContext ctx = createMinimalContext();
            String json = ctx.toJson();

            ObjectMapper mapper = new ObjectMapper();
            // Should not throw
            var node = mapper.readTree(json);
            assertThat(node).isNotNull();
            assertThat(node.has("userId")).isTrue();
            assertThat(node.get("userId").asText()).isEqualTo("user-001");
        }

        @Test
        @DisplayName("Should contain core fields in JSON output")
        void shouldContainCoreFields() throws Exception {
            HCADContext ctx = createMinimalContext();
            String json = ctx.toJson();

            ObjectMapper mapper = new ObjectMapper();
            var node = mapper.readTree(json);

            assertThat(node.has("sessionId")).isTrue();
            assertThat(node.has("requestPath")).isTrue();
            assertThat(node.has("httpMethod")).isTrue();
            assertThat(node.has("remoteIp")).isTrue();
            assertThat(node.has("trustScore")).isTrue();
        }
    }

    @Nested
    @DisplayName("toCompactString")
    class ToCompactStringTest {

        @Test
        @DisplayName("Should contain expected format segments")
        void shouldContainExpectedSegments() {
            HCADContext ctx = createMinimalContext();
            String compact = ctx.toCompactString();

            assertThat(compact).contains("User:user-001");
            assertThat(compact).contains("IP:192.168.1.1");
            assertThat(compact).contains("Path:/api/test");
            assertThat(compact).contains("Method:GET");
        }

        @Test
        @DisplayName("Should use 'anonymous' for null userId")
        void shouldUseAnonymousForNullUserId() {
            HCADContext ctx = HCADContext.builder()
                    .requestPath("/test")
                    .httpMethod("GET")
                    .remoteIp("10.0.0.1")
                    .timestamp(Instant.now())
                    .recentRequestCount(0)
                    .isNewSession(false)
                    .isNewDevice(false)
                    .isNewUser(false)
                    .build();
            String compact = ctx.toCompactString();
            assertThat(compact).contains("User:anonymous");
        }
    }

    @Nested
    @DisplayName("Getter fallback logic")
    class GetterFallbackTest {

        @Test
        @DisplayName("getSourceIp should return sourceIp when set")
        void shouldReturnSourceIpWhenSet() {
            HCADContext ctx = HCADContext.builder()
                    .sourceIp("10.0.0.1")
                    .remoteIp("192.168.1.1")
                    .build();
            assertThat(ctx.getSourceIp()).isEqualTo("10.0.0.1");
        }

        @Test
        @DisplayName("getSourceIp should fallback to remoteIp when sourceIp is null")
        void shouldFallbackToRemoteIpWhenSourceIpNull() {
            HCADContext ctx = HCADContext.builder()
                    .remoteIp("192.168.1.1")
                    .build();
            assertThat(ctx.getSourceIp()).isEqualTo("192.168.1.1");
        }

        @Test
        @DisplayName("getTrustScore should return trustScore when set")
        void shouldReturnTrustScoreWhenSet() {
            HCADContext ctx = HCADContext.builder()
                    .trustScore(0.9)
                    .currentTrustScore(0.7)
                    .build();
            assertThat(ctx.getTrustScore()).isEqualTo(0.9);
        }

        @Test
        @DisplayName("getTrustScore should fallback to currentTrustScore when trustScore is null")
        void shouldFallbackToCurrentTrustScore() {
            HCADContext ctx = HCADContext.builder()
                    .currentTrustScore(0.7)
                    .build();
            assertThat(ctx.getTrustScore()).isEqualTo(0.7);
        }

        @Test
        @DisplayName("getActivityVelocity should return activityVelocity when set")
        void shouldReturnActivityVelocityWhenSet() {
            HCADContext ctx = HCADContext.builder()
                    .activityVelocity(3.5)
                    .recentRequestCount(10)
                    .build();
            assertThat(ctx.getActivityVelocity()).isEqualTo(3.5);
        }

        @Test
        @DisplayName("getActivityVelocity should fallback to recentRequestCount/5.0")
        void shouldFallbackToRecentRequestCountDivided() {
            HCADContext ctx = HCADContext.builder()
                    .recentRequestCount(25)
                    .build();
            assertThat(ctx.getActivityVelocity()).isEqualTo(5.0);
        }

        @Test
        @DisplayName("getActivityVelocity should return 0.0 when no data available")
        void shouldReturnZeroWhenNoActivityData() {
            HCADContext ctx = HCADContext.builder().build();
            assertThat(ctx.getActivityVelocity()).isEqualTo(0.0);
        }

        @Test
        @DisplayName("getAnomalyScore should return anomalyScore when set")
        void shouldReturnAnomalyScoreWhenSet() {
            HCADContext ctx = HCADContext.builder()
                    .anomalyScore(0.3)
                    .currentTrustScore(0.8)
                    .build();
            assertThat(ctx.getAnomalyScore()).isEqualTo(0.3);
        }

        @Test
        @DisplayName("getAnomalyScore should fallback to 1.0 - currentTrustScore")
        void shouldFallbackToOneMinusTrustScore() {
            HCADContext ctx = HCADContext.builder()
                    .currentTrustScore(0.8)
                    .build();
            assertThat(ctx.getAnomalyScore()).isCloseTo(0.2, org.assertj.core.data.Offset.offset(1e-10));
        }

        @Test
        @DisplayName("getAnomalyScore should return 0.5 when no data available")
        void shouldReturnHalfWhenNoAnomalyData() {
            HCADContext ctx = HCADContext.builder().build();
            assertThat(ctx.getAnomalyScore()).isEqualTo(0.5);
        }

        @Test
        @DisplayName("getDeviceId should return deviceId when set")
        void shouldReturnDeviceIdWhenSet() {
            HCADContext ctx = HCADContext.builder()
                    .deviceId("device-123")
                    .userAgent("TestAgent/1.0")
                    .build();
            assertThat(ctx.getDeviceId()).isEqualTo("device-123");
        }

        @Test
        @DisplayName("getDeviceId should fallback to userAgent hashCode")
        void shouldFallbackToUserAgentHashCode() {
            String userAgent = "TestAgent/1.0";
            HCADContext ctx = HCADContext.builder()
                    .userAgent(userAgent)
                    .build();
            assertThat(ctx.getDeviceId()).isEqualTo(String.valueOf(userAgent.hashCode()));
        }

        @Test
        @DisplayName("getDeviceId should return null when no data available")
        void shouldReturnNullWhenNoDeviceData() {
            HCADContext ctx = HCADContext.builder().build();
            assertThat(ctx.getDeviceId()).isNull();
        }
    }

    @Nested
    @DisplayName("baselineConfidence default")
    class BaselineConfidenceTest {

        @Test
        @DisplayName("Should default to 0.5 when not explicitly set")
        void shouldDefaultToHalf() {
            HCADContext ctx = HCADContext.builder().build();
            assertThat(ctx.getBaselineConfidence()).isEqualTo(0.5);
        }

        @Test
        @DisplayName("Should use provided value when explicitly set")
        void shouldUseProvidedValue() {
            HCADContext ctx = HCADContext.builder()
                    .baselineConfidence(0.9)
                    .build();
            assertThat(ctx.getBaselineConfidence()).isEqualTo(0.9);
        }
    }
}
