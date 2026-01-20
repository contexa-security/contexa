package io.contexa.contexaidentity.security.token.wrapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.nio.charset.StandardCharsets;
import java.util.*;


public class OAuth2TokenRequestWrapper extends HttpServletRequestWrapper {

    private final String username;
    private final String deviceId;
    private final Map<String, String[]> oauth2Parameters;

    
    public OAuth2TokenRequestWrapper(
            HttpServletRequest request,
            String username,
            String deviceId) {

        super(request);
        this.username = username;
        this.deviceId = deviceId;
        this.oauth2Parameters = buildOAuth2Parameters();
    }

    
    private Map<String, String[]> buildOAuth2Parameters() {
        Map<String, String[]> params = new HashMap<>();

        
        params.put("grant_type", new String[]{"urn:ietf:params:oauth:grant-type:authenticated-user"});

        
        params.put("username", new String[]{username});

        
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

    
    @Override
    public String getHeader(String name) {
        if ("Authorization".equalsIgnoreCase(name)) {
            
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

    
    @Override
    public String getMethod() {
        return "POST";
    }
}
