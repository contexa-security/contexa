package io.contexa.showcase.portal.web;

import org.springframework.boot.web.server.MimeMappings;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.EncodedResourceResolver;
import org.springframework.web.servlet.resource.PathResourceResolver;

import java.io.IOException;

/**
 * Serves the visitor web application. Existing static files are returned as they are; any other
 * browser route falls back to index.html so client-side routing works on reload and deep links.
 * API and actuator paths never fall back, so an unknown API path stays a 404 instead of an HTML page.
 * A browser that accepts Brotli gets the copy the web build wrote next to each text file (C-13).
 * The guide videos' caption tracks are served as text/vtt (가이드영상-계획.md).
 */
@Configuration(proxyBeanMethods = false)
public class SinglePageApplicationConfiguration implements WebMvcConfigurer {

    private static final ClassPathResource INDEX = new ClassPathResource("/static/index.html");

    /**
     * The container's default list does not name WebVTT, so caption tracks would go out as octet-stream, and a
     * browser that checks the type ignores such a track. The one type is added to the container's list.
     */
    @Bean
    static WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> captionTrackType() {
        return factory -> {
            MimeMappings caption = new MimeMappings();
            caption.add("vtt", "text/vtt");
            factory.addMimeMappings(caption);
        };
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/")
                .resourceChain(true)
                .addResolver(new EncodedResourceResolver())
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String resourcePath, Resource location) throws IOException {
                        Resource requested = location.createRelative(resourcePath);
                        if (requested.exists() && requested.isReadable()) {
                            return requested;
                        }
                        if (resourcePath.startsWith("api/") || resourcePath.startsWith("actuator/")
                                || resourcePath.contains(".")) {
                            return null;
                        }
                        return INDEX.exists() ? INDEX : null;
                    }
                });
    }
}
