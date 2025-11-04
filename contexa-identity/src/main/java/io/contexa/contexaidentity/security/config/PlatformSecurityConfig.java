package io.contexa.contexaidentity.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.RestAuthenticationProvider;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationConverter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class PlatformSecurityConfig {

    private final ApplicationContext applicationContext;
    private final ObjectMapper objectMapper;
    private final RestAuthenticationProvider restAuthenticationProvider;
    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {
        log.info("Configuring Platform Security DSL...");

        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
                http
                    .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers(
                                    "/css/**", "/js/**", "/images/**", "/favicon.ico",
                                    "/authMode","/",
//                                    "/", "/authMode","/home",
                                    "/loginForm", "/register",
                                    "/loginOtt", "/ott/sent",
                                    "/loginPasskey",
                                    "/mfa/select-factor","/mfa/ott/request-code-ui", "/mfa/challenge/ott", "/mfa/challenge/passkey", "/mfa/failure",
                                    "/api/register",
                                    "/api/auth/login", "/api/auth/refresh",
                                    "/api/ott/generate",
                                    "/webauthn/register/options", "/webauthn/register",
                                    "/webauthn/authenticate/options", "/login/webauthn",
                                    "/api/mfa/select-factor", "/api/mfa/request-ott-code", "/api/mfa/config"
                            ).permitAll()
                            .requestMatchers("/users", "/api/users").hasRole("USER")
                            .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated()
                    )
                    .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                    .sessionManagement(session -> session
                                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    )
                    .logout(logout -> logout
                            .addLogoutHandler(applicationContext.getBean("oauth2LogoutHandler", LogoutHandler.class))
                            .logoutSuccessHandler((request, response, authentication) -> {
                                response.setStatus(HttpServletResponse.SC_OK);
                                response.setContentType("application/json;charset=UTF-8");
                                objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                            })
                            .invalidateHttpSession(false)
                            .clearAuthentication(true)
                    )
                ;
        };
        return registry
                .global(globalHttpCustomizer)
                .mfa(mfa -> mfa
                        .primaryAuthentication(auth -> auth.restLogin(rest ->
                                rest.securityContextRepository(new HttpSessionSecurityContextRepository())))
                        .ott(Customizer.withDefaults())
                        .passkey(Customizer.withDefaults())
                        .order(20)
                ).oauth2(Customizer.withDefaults())
                .build();
    }
}