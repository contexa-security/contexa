package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class RequestInfoExtractorTest {

    @Test
    @DisplayName("request attribute濡??ㅻ┛ previousPath? interval? event metadata濡??밴꺽?????덇쾶 異붿텧?섏뼱???쒕떎")
    void extractShouldIncludeAuthMethodAndResourceHintsFromRequestAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-001");
        request.addHeader("X-Simulated-User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        request.setAttribute("hcad.auth_method", "mfa");
        request.setAttribute("hcad.resource_sensitivity", "HIGH");
        request.setAttribute("hcad.resource_business_label", "Sensitive Security Test Resource resource-001");
        request.setAttribute("hcad.mfa_verified", true);
        request.setAttribute("hcad.previous_path", "/admin/api/security-test/sensitive/resource-000");
        request.setAttribute("hcad.last_request_interval_ms", 4_200L);

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getAuthMethod()).isEqualTo("mfa");
        assertThat(requestInfo.getResourceSensitivity()).isEqualTo("HIGH");
        assertThat(requestInfo.getResourceBusinessLabel()).isEqualTo("Sensitive Security Test Resource resource-001");
        assertThat(requestInfo.getMfaVerified()).isTrue();
        // ????媛믪씠 null?대㈃ HCAD媛 怨꾩궛??previousPath? interval??event metadata濡??밴꺽?섏? 紐삵븯怨?
        // Layer1??data store瑜??ㅼ떆 ?쎌쑝硫댁꽌 ?꾩옱 ?붿껌 寃쎈줈瑜?previousPath濡??ㅼ뿼?쒗궗 ???덈떎.
        assertThat(requestInfo.getPreviousPath()).isEqualTo("/admin/api/security-test/sensitive/resource-000");
        assertThat(requestInfo.getLastRequestIntervalMs()).isEqualTo(4_200L);
        assertThat(requestInfo.getUserAgent()).contains("Chrome/120");
    }
    @Test
    @DisplayName("관측 시각 헤더는 request info observedAt으로 승격되어 이후 event와 baseline 시간축의 기준이 되어야 한다")
    void extractShouldIncludeObservedAtFromHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-observed-at");
        request.addHeader("X-Contexa-Observed-At", "2026-02-03T09:15:00+09:00");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        // 시간이 실제 웹 요청 헤더에서 올라와야 장기 회차 benchmark가
        // "몇 초 동안의 반복 호출"이 아니라 "몇 주/몇 달 패턴"으로 학습된다.
        assertThat(requestInfo.getObservedAt()).isNotNull();
        assertThat(requestInfo.getObservedAt().toString()).isEqualTo("2026-02-03T00:15:00Z");
    }
}
