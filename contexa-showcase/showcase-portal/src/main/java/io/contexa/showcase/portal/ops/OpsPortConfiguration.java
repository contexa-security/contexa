package io.contexa.showcase.portal.ops;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * The operator API ({@code /ops/**}: template learning, orchestrated runs) listens on its own port, which the
 * production-shaped stack never publishes (deck p.37: operation screens and internal addresses stay hidden from
 * visitors). On the visitor port {@code /ops/**} does not exist, and the operator port serves nothing else.
 * Disabled unless {@code showcase.portal.ops.port} is set.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class OpsPortConfiguration {

    public static final String OPS_PREFIX = "/ops/";

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> opsConnector(
            @Value("${showcase.portal.ops.port}") int port,
            @Value("${showcase.portal.ops.address:127.0.0.1}") String address) {
        return factory -> {
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setPort(port);
            connector.setProperty("address", address);
            factory.addAdditionalTomcatConnectors(connector);
        };
    }

    @Bean
    FilterRegistrationBean<OncePerRequestFilter> opsPortFilter(@Value("${showcase.portal.ops.port}") int port) {
        FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(
                new OncePerRequestFilter() {
                    @Override
                    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                                    FilterChain chain) throws ServletException, IOException {
                        boolean opsPort = request.getLocalPort() == port;
                        boolean opsPath = request.getRequestURI().startsWith(OPS_PREFIX);
                        if (opsPort != opsPath) {
                            response.sendError(HttpServletResponse.SC_NOT_FOUND);
                            return;
                        }
                        chain.doFilter(request, response);
                    }
                });
        registration.setName("opsPortFilter");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
