package io.contexa.contexacore.security;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.net.URL;
import java.net.URLClassLoader;

import static org.assertj.core.api.Assertions.assertThat;

class AISecurityContextOptionalOAuth2Test {
    @Test void sessionOnlyRuntimeDoesNotRequireResourceServerClasses() throws Exception {
        String supportName = AISecurityContextSupport.class.getName();
        String jwtName = JwtAuthenticationToken.class.getName();
        URL classes = AISecurityContextSupport.class.getProtectionDomain().getCodeSource().getLocation();
        try (URLClassLoader isolated = new URLClassLoader(new URL[]{classes}, getClass().getClassLoader()) {
            @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (jwtName.equals(name)) throw new ClassNotFoundException(name);
                if (supportName.equals(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null) loaded = findClass(name);
                    if (resolve) resolveClass(loaded);
                    return loaded;
                }
                return super.loadClass(name, resolve);
            }
        }) {
            Class<?> supportClass = isolated.loadClass(supportName);
            Object support = supportClass.getConstructor(SecurityZeroTrustProperties.class,
                    ZeroTrustSecurityService.class, SessionIdResolver.class)
                    .newInstance(new SecurityZeroTrustProperties(), null, null);
            MockHttpServletRequest request = new MockHttpServletRequest();
            String sessionId = request.getSession().getId();
            Object resolved = supportClass.getMethod("resolveIdentifier", HttpServletRequest.class, Authentication.class)
                    .invoke(support, request, null);
            assertThat(resolved).isEqualTo(sessionId);
        }
    }
}
