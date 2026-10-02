package io.contexa.demo.platform.configuration;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;

@Configuration(proxyBeanMethods = false)
@Profile("contexa")
public class PlatformStaticResourceConfig {

    @Bean
    WebSecurityCustomizer platformStaticResources() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .requestMatchers(HttpMethod.GET, "/contexa/css/**", "/contexa/js/**")
                .requestMatchers(HttpMethod.HEAD, "/contexa/css/**", "/contexa/js/**");
    }
}
