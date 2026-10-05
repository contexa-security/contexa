package io.contexa.showcase.portal.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P5-SEC-05 on a real portal server: the client address the daily limits read comes from forwarding headers only when
 * they arrive from a configured trusted proxy; anyone else's forwarding header is ignored. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
class ClientAddressIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();

    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
    }

    /**
     * Answers the client address the portal sees, as the daily limits read it. A filter rather than a controller, so
     * no test mapping reaches the visitor-path allowlist of {@link VisitorPortExposureIntegrationTest}.
     */
    @TestConfiguration
    static class AddressEcho {
        @Bean
        FilterRegistrationBean<OncePerRequestFilter> addressEcho() {
            FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(
                    new OncePerRequestFilter() {
                        @Override
                        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                                        FilterChain chain) throws IOException {
                            response.setContentType("text/plain");
                            response.getWriter().write(request.getRemoteAddr());
                        }
                    });
            registration.addUrlPatterns("/echo-address");
            registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return registration;
        }
    }

    private static String echo(TestRestTemplate http, String forwardedFor) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Forwarded-For", forwardedFor);
        return http.exchange("/echo-address", HttpMethod.GET, new HttpEntity<>(headers), String.class).getBody();
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
            "server.address=127.0.0.1", "server.forward-headers-strategy=native",
            "server.tomcat.remoteip.internal-proxies=127\\.0\\.0\\.1"})
    @Import(AddressEcho.class)
    class FromTheTrustedProxy {

        @DynamicPropertySource
        static void properties(DynamicPropertyRegistry registry) {
            database(registry);
        }

        @Autowired
        TestRestTemplate http;

        @Test
        void theForwardedClientAddressIsUsed() {
            assertThat(echo(http, "203.0.113.9")).isEqualTo("203.0.113.9");
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
            "server.address=127.0.0.1", "server.forward-headers-strategy=native",
            "server.tomcat.remoteip.internal-proxies=10\\.9\\.9\\.9"})
    @Import(AddressEcho.class)
    class FromAnyOtherAddress {

        @DynamicPropertySource
        static void properties(DynamicPropertyRegistry registry) {
            database(registry);
        }

        @Autowired
        TestRestTemplate http;

        @Test
        void aForgedForwardingHeaderIsIgnored() {
            assertThat(echo(http, "203.0.113.9")).isEqualTo("127.0.0.1");
        }
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
