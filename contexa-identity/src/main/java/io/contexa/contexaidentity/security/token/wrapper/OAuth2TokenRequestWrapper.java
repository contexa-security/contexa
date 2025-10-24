package io.contexa.contexaidentity.security.token.wrapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * OAuth2 토큰 요청을 위한 HttpServletRequest 래퍼
 *
 * <p>실제 HttpServletRequest를 래핑하여 OAuth2 토큰 엔드포인트 요청으로 변환합니다.
 * 원본 요청의 세션, IP, 헤더 등은 그대로 유지하면서 필요한 값만 오버라이드합니다.
 *
 * <h3>변환되는 값</h3>
 * <ul>
 *   <li>URI: "/oauth2/token"</li>
 *   <li>파라미터: grant_type, username, client_id, client_secret, device_id</li>
 * </ul>
 *
 * <h3>보존되는 값</h3>
 * <ul>
 *   <li>HTTP 세션</li>
 *   <li>클라이언트 IP (RemoteAddr)</li>
 *   <li>User-Agent 및 모든 헤더</li>
 *   <li>요청 메소드 (POST)</li>
 * </ul>
 *
 * @since 2025.01
 */
public class OAuth2TokenRequestWrapper extends HttpServletRequestWrapper {

    private final String username;
    private final String deviceId;
    private final Map<String, String[]> oauth2Parameters;

    /**
     * OAuth2TokenRequestWrapper 생성자
     *
     * @param request 원본 HttpServletRequest (세션/IP/헤더 보존용)
     * @param username 사용자 이름
     * @param deviceId 디바이스 ID (nullable)
     */
    public OAuth2TokenRequestWrapper(
            HttpServletRequest request,
            String username,
            String deviceId) {

        super(request);
        this.username = username;
        this.deviceId = deviceId;
        this.oauth2Parameters = buildOAuth2Parameters();
    }

    /**
     * OAuth2 토큰 요청 파라미터 생성
     *
     * <p>client_id, client_secret는 파라미터가 아닌 Authorization 헤더로 전달됩니다.
     */
    private Map<String, String[]> buildOAuth2Parameters() {
        Map<String, String[]> params = new HashMap<>();

        // OAuth2 Grant Type
        params.put("grant_type", new String[]{"urn:ietf:params:oauth:grant-type:authenticated-user"});

        // 사용자 이름
        params.put("username", new String[]{username});

        // Device ID (선택적)
        if (deviceId != null) {
            params.put("device_id", new String[]{deviceId});
        }

        return params;
    }

    @Override
    public String getRequestURI() {
        return "/oauth2/token";
    }

    @Override
    public StringBuffer getRequestURL() {
        StringBuffer url = new StringBuffer();
        url.append(getScheme())
           .append("://")
           .append(getServerName());

        int port = getServerPort();
        if (port != 80 && port != 443) {
            url.append(':').append(port);
        }

        url.append("/oauth2/token");
        return url;
    }

    @Override
    public String getServletPath() {
        return "/oauth2/token";
    }

    @Override
    public String getPathInfo() {
        return null;
    }

    @Override
    public String getParameter(String name) {
        String[] values = oauth2Parameters.get(name);
        return (values != null && values.length > 0) ? values[0] : null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return Collections.unmodifiableMap(oauth2Parameters);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(oauth2Parameters.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return oauth2Parameters.get(name);
    }

    /**
     * HTTP Basic Authentication 헤더 추가
     *
     * <p>Spring Authorization Server는 client_secret_basic 방식을 기본으로 사용하므로
     * Authorization 헤더에 "Basic base64(client_id:client_secret)" 형식으로 전달해야 합니다.
     */
    @Override
    public String getHeader(String name) {
        if ("Authorization".equalsIgnoreCase(name)) {
            // client_id:client_secret를 Base64 인코딩
            String credentials = "aidc-client:secret";
            String base64Credentials = Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            return "Basic " + base64Credentials;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if ("Authorization".equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(getHeader(name)));
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> headerNames = new HashSet<>();
        Enumeration<String> originalHeaders = super.getHeaderNames();
        if (originalHeaders != null) {
            while (originalHeaders.hasMoreElements()) {
                headerNames.add(originalHeaders.nextElement());
            }
        }
        headerNames.add("Authorization");
        return Collections.enumeration(headerNames);
    }

    /**
     * HTTP Method는 POST로 고정
     *
     * <p>OAuth2 토큰 엔드포인트는 POST 메소드만 허용합니다.
     */
    @Override
    public String getMethod() {
        return "POST";
    }
}
