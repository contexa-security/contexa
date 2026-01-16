package io.contexa.contexacore.hcad.util;

/**
 * AI Native v8.8: User-Agent 파싱 공통 유틸리티 클래스
 *
 * 목적:
 * - BaselineLearningService와 AbstractTieredStrategy의 중복 로직 통합
 * - 일관된 UA 파싱 및 비교 로직 제공
 * - 테스트 용이성 향상
 *
 * 주요 기능:
 * - UA 시그니처 정규화 (예: "Chrome/120 (Windows)")
 * - OS 추출 (모바일 OS 우선 검사)
 * - 브라우저 추출 (메이저 버전만)
 * - UA 유사도 비교 (세션 하이재킹 탐지용)
 */
public final class UserAgentParser {

    // 지원하는 브라우저 키워드 (우선순위 순서)
    private static final String[] BROWSER_KEYWORDS = {
        "Edg/",      // Edge (Chromium 기반) - Chrome보다 먼저 검사
        "Chrome/",   // Chrome
        "Firefox/",  // Firefox
        "Safari/",   // Safari (Chrome, Edge 제외 후)
        "Opera/",    // Opera
        "MSIE ",     // IE (레거시)
        "Trident/"   // IE 11
    };

    // 지원하는 OS 키워드 (우선순위 순서 - 모바일 우선)
    // Android가 Linux를 포함하므로 모바일 OS를 먼저 검사
    private static final String[] OS_KEYWORDS = {
        "Android",      // 모바일 (Linux 포함)
        "iPhone",       // iOS
        "iPad",         // iOS
        "iPod",         // iOS
        "iOS",          // iOS (일부 UA에 명시적으로 포함)
        "Windows",      // 데스크톱
        "Macintosh",    // macOS
        "Mac OS",       // macOS
        "CrOS",         // ChromeOS
        "Linux"         // Linux (Android 제외 후)
    };

    // OS 정규화 매핑
    private static final String[][] OS_NORMALIZE_MAP = {
        {"Android", "Android"},
        {"iPhone", "iOS"},
        {"iPad", "iOS"},
        {"iPod", "iOS"},
        {"iOS", "iOS"},
        {"Windows", "Windows"},
        {"Macintosh", "Mac"},
        {"Mac OS", "Mac"},
        {"CrOS", "ChromeOS"},
        {"Linux", "Linux"}
    };

    private UserAgentParser() {
        // 유틸리티 클래스 - 인스턴스화 방지
    }

    /**
     * User-Agent 문자열을 정규화된 시그니처로 변환
     *
     * 예: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.6099.71"
     *     → "Chrome/120 (Windows)"
     *
     * @param userAgent 원본 User-Agent 문자열
     * @return 정규화된 시그니처 (예: "Chrome/120 (Windows)")
     */
    public static String extractSignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser (Desktop)";
        }

        String browser = extractBrowser(userAgent);
        String os = extractOS(userAgent);

        return browser + " (" + os + ")";
    }

    /**
     * User-Agent에서 브라우저명과 메이저 버전 추출
     *
     * @param userAgent 원본 User-Agent 문자열
     * @return 브라우저/메이저버전 (예: "Chrome/120") 또는 "Browser"
     */
    public static String extractBrowser(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser";
        }

        // Edge 검사 (Chrome보다 먼저 - Edg/는 Chrome도 포함)
        if (userAgent.contains("Edg/")) {
            String version = extractMajorVersion(userAgent, "Edg/");
            return "Edge/" + version;
        }

        // Chrome 검사 (Edge 제외 후)
        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            String version = extractMajorVersion(userAgent, "Chrome/");
            return "Chrome/" + version;
        }

        // Firefox 검사
        if (userAgent.contains("Firefox/")) {
            String version = extractMajorVersion(userAgent, "Firefox/");
            return "Firefox/" + version;
        }

        // Safari 검사 (Chrome, Edge 제외 후)
        // Safari는 "Version/"에서 버전을 추출
        if (userAgent.contains("Safari/") && !userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            String version = extractMajorVersion(userAgent, "Version/");
            return "Safari/" + version;
        }

        // Opera 검사
        if (userAgent.contains("Opera/") || userAgent.contains("OPR/")) {
            String prefix = userAgent.contains("OPR/") ? "OPR/" : "Opera/";
            String version = extractMajorVersion(userAgent, prefix);
            return "Opera/" + version;
        }

        // IE 검사 (레거시)
        if (userAgent.contains("MSIE ") || userAgent.contains("Trident/")) {
            return "IE/11";  // 단순화
        }

        return "Browser";
    }

    /**
     * User-Agent에서 OS 추출
     *
     * 우선순위:
     * 1. 모바일 OS (Android, iOS) - Android가 Linux를 포함하므로 먼저 검사
     * 2. 데스크톱 OS (Windows, Mac, ChromeOS, Linux)
     * 3. 기본값: "Desktop"
     *
     * @param userAgent 원본 User-Agent 문자열
     * @return 정규화된 OS (예: "Windows", "Android", "iOS", "Mac", "ChromeOS", "Linux", "Desktop")
     */
    public static String extractOS(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Desktop";
        }

        // 모바일 OS 우선 검사 (Android가 Linux를 포함)
        if (userAgent.contains("Android")) {
            return "Android";
        }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")
                || userAgent.contains("iPod") || userAgent.contains("iOS")) {
            return "iOS";
        }

        // 데스크톱 OS
        if (userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Macintosh") || userAgent.contains("Mac OS")) {
            return "Mac";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }
        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        // 모바일 패턴 (OS 특정 불가)
        if (userAgent.contains("Mobile") || userAgent.contains("Tablet")) {
            return "Mobile";
        }

        return "Desktop";
    }

    /**
     * 두 User-Agent가 유사한지 비교 (세션 하이재킹 탐지용)
     *
     * 유사 조건:
     * - 동일한 브라우저 (메이저 버전 무관)
     * - 동일한 OS
     *
     * @param ua1 첫 번째 User-Agent
     * @param ua2 두 번째 User-Agent
     * @return 유사하면 true, 아니면 false (하이재킹 의심)
     */
    public static boolean isSimilar(String ua1, String ua2) {
        if (ua1 == null || ua2 == null) {
            return false;
        }

        // 브라우저 비교 (브라우저명만, 버전 무관)
        String browser1 = extractBrowserName(ua1);
        String browser2 = extractBrowserName(ua2);

        if (browser1 == null || browser2 == null) {
            return false;
        }
        if (!browser1.equals(browser2)) {
            return false;  // 브라우저 변경 = 하이재킹 의심
        }

        // OS 비교
        String os1 = extractOS(ua1);
        String os2 = extractOS(ua2);

        // OS가 다르면 하이재킹 의심
        if (!os1.equals(os2)) {
            return false;
        }

        return true;
    }

    /**
     * 시그니처에서 브라우저/버전 추출
     *
     * @param signature UA 시그니처 (예: "Chrome/120 (Windows)")
     * @return 브라우저/버전 (예: "Chrome/120") 또는 null
     */
    public static String extractBrowserFromSignature(String signature) {
        if (signature == null) {
            return null;
        }
        int spaceIdx = signature.indexOf(" ");
        if (spaceIdx > 0) {
            return signature.substring(0, spaceIdx);
        }
        return signature;
    }

    /**
     * 시그니처에서 OS 추출
     *
     * @param signature UA 시그니처 (예: "Chrome/120 (Windows)")
     * @return OS (예: "Windows") 또는 null
     */
    public static String extractOSFromSignature(String signature) {
        if (signature == null) {
            return null;
        }
        int openParen = signature.indexOf("(");
        int closeParen = signature.indexOf(")");
        if (openParen > 0 && closeParen > openParen) {
            return signature.substring(openParen + 1, closeParen);
        }
        return null;
    }

    /**
     * 브라우저명만 추출 (버전 제외)
     *
     * @param userAgent 원본 User-Agent 또는 시그니처
     * @return 브라우저명 (예: "Chrome") 또는 null
     */
    public static String extractBrowserName(String userAgent) {
        if (userAgent == null) {
            return null;
        }

        // 시그니처 형식인 경우 (예: "Chrome/120 (Windows)")
        if (userAgent.contains("(") && userAgent.contains(")")) {
            String browser = extractBrowserFromSignature(userAgent);
            if (browser != null && browser.contains("/")) {
                return browser.split("/")[0];
            }
            return browser;
        }

        // 원본 UA 형식인 경우
        for (String keyword : new String[]{"Edge", "Edg", "Chrome", "Firefox", "Safari", "Opera", "MSIE", "Trident"}) {
            if (userAgent.contains(keyword)) {
                // Edge와 Edg 통합
                if (keyword.equals("Edg")) {
                    return "Edge";
                }
                // Trident는 IE로 매핑
                if (keyword.equals("Trident")) {
                    return "IE";
                }
                return keyword;
            }
        }

        return null;
    }

    /**
     * 메이저 버전만 추출
     *
     * @param userAgent 원본 User-Agent 문자열
     * @param prefix 브라우저 prefix (예: "Chrome/")
     * @return 메이저 버전 (예: "120") 또는 "0"
     */
    private static String extractMajorVersion(String userAgent, String prefix) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) {
            return "0";
        }

        int start = idx + prefix.length();
        if (start >= userAgent.length()) {
            return "0";
        }

        // 메이저 버전만 추출 (첫 번째 . 또는 공백까지)
        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) {
            return "0";
        }

        return userAgent.substring(start, end);
    }
}
