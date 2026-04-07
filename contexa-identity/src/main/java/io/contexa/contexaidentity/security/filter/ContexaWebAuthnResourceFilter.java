package io.contexa.contexaidentity.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Serves spring-security-webauthn.js at a configurable URL path.
 * Replacement for DefaultResourcesFilter.webauthn() that supports urlPrefix.
 */
public class ContexaWebAuthnResourceFilter extends GenericFilterBean {

    private final RequestMatcher matcher;
    private final ClassPathResource resource;
    private final MediaType mediaType;

    private ContexaWebAuthnResourceFilter(RequestMatcher matcher) {
        this.matcher = matcher;
        this.resource = new ClassPathResource("org/springframework/security/spring-security-webauthn.js");
        this.mediaType = new MediaType("text", "javascript", StandardCharsets.UTF_8);
    }

    public static ContexaWebAuthnResourceFilter create(String servingPath) {
        RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.GET, servingPath);
        return new ContexaWebAuthnResourceFilter(requestMatcher);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request instanceof HttpServletRequest httpRequest && this.matcher.matches(httpRequest)) {
            response.setContentType(this.mediaType.toString());
            response.getWriter().write(this.resource.getContentAsString(StandardCharsets.UTF_8));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
