package io.contexa.contexaidentity.security.filter;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HTML 템플릿 빌더 유틸리티
 *
 * <p>
 * Spring Security의 HtmlTemplates 패턴을 차용하여 HTML 생성 시
 * 템플릿과 로직을 분리하고, XSS 방어를 자동화합니다.
 * </p>
 *
 * <p>
 * 사용 예시:
 * </p>
 * <pre>
 * String html = MfaHtmlTemplates.fromTemplate(TEMPLATE)
 *     .withValue("title", userInput)      // XSS 방어: 자동 이스케이프
 *     .withRawHtml("content", safeHtml)   // Raw HTML 삽입 (이미 안전한 HTML)
 *     .render();
 * </pre>
 *
 * @see org.springframework.security.web.authentication.ui.HtmlTemplates
 */
public class MfaHtmlTemplates {

    private MfaHtmlTemplates() {
        // 유틸리티 클래스: 인스턴스화 방지
    }

    /**
     * 템플릿 문자열로부터 Builder 생성
     *
     * @param template 템플릿 문자열 ({{key}} 형태의 플레이스홀더 포함)
     * @return Builder 인스턴스
     */
    public static Builder fromTemplate(String template) {
        return new Builder(template);
    }

    /**
     * HTML 템플릿 빌더
     */
    public static class Builder {
        private final String template;
        private final Map<String, String> replacements = new LinkedHashMap<>();

        Builder(String template) {
            this.template = template;
        }

        /**
         * 템플릿 변수에 값을 설정 (XSS 방어: 자동 HTML 이스케이프)
         *
         * @param key 템플릿 변수명 ({{key}} 형태로 사용)
         * @param value 설정할 값 (HTML 이스케이프 적용됨)
         * @return Builder (메서드 체이닝)
         */
        public Builder withValue(String key, String value) {
            this.replacements.put("{{" + key + "}}", escapeHtml(value));
            return this;
        }

        /**
         * 템플릿 변수에 Raw HTML을 설정 (이스케이프 없이 직접 삽입)
         *
         * <p>
         * 주의: 이 메서드는 이미 안전한 HTML에만 사용해야 합니다.
         * 사용자 입력을 직접 삽입하면 XSS 취약점이 발생할 수 있습니다.
         * </p>
         *
         * @param key 템플릿 변수명
         * @param value Raw HTML 값 (이스케이프 없이 직접 삽입)
         * @return Builder (메서드 체이닝)
         */
        public Builder withRawHtml(String key, String value) {
            this.replacements.put("{{" + key + "}}", value);
            return this;
        }

        /**
         * 템플릿을 렌더링하여 최종 HTML 생성
         *
         * @return 렌더링된 HTML 문자열
         */
        public String render() {
            String result = this.template;
            for (Map.Entry<String, String> entry : this.replacements.entrySet()) {
                result = result.replace(entry.getKey(), entry.getValue());
            }
            return result;
        }

        /**
         * HTML 특수 문자 이스케이프 (XSS 방어)
         *
         * @param input 이스케이프할 문자열
         * @return 이스케이프된 문자열
         */
        private String escapeHtml(String input) {
            if (input == null) {
                return "";
            }
            return input.replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;")
                       .replace("\"", "&quot;")
                       .replace("'", "&#x27;")
                       .replace("/", "&#x2F;");
        }
    }
}
