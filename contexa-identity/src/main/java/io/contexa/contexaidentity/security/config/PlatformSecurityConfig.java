package io.contexa.contexaidentity.security.config;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class PlatformSecurityConfig {

    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {
        log.info("Configuring Platform Security DSL...");

        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
                http
                    .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers(
                                    "/css/**", "/js/**", "/images/**", "/favicon.ico",
//                                    "/authMode","/",
                                    "/", "/authMode","/home",
                                    "/loginForm", "/register","/login",
                                    "/loginOtt", "/ott/sent",
                                    "/loginPasskey","/login/mfa-ott",
                                    "/mfa/select-factor","/mfa/ott/request-code-ui", "/mfa/challenge/ott",
                                    "/mfa/challenge/passkey", "/mfa/failure","/mfa/ott/generate-code","/mfa/ott/code-sent",
                                    "/api/register",
                                    "/api/auth/login", "/api/auth/refresh",
                                    "/api/ott/generate",
                                    "/webauthn/register/options", "/webauthn/register","/login/mfa-webauthn",
                                    "/webauthn/authenticate/options", "/login/webauthn",
                                    "/api/mfa/select-factor", "/api/mfa/request-ott-code", "/api/mfa/config"
                            ).permitAll()
                            .requestMatchers("/users", "/api/users").hasRole("USER")
                            .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated()
                    )
                    /*.logout(logout -> logout
                            .addLogoutHandler(applicationContext.getBean("oauth2LogoutHandler", LogoutHandler.class))
                            .logoutSuccessHandler((request, response, authentication) -> {
                                response.setStatus(HttpServletResponse.SC_OK);
                                response.setContentType("application/json;charset=UTF-8");
                                objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                            })
                            .invalidateHttpSession(false)
                            .clearAuthentication(true)
                    )*/
                    .securityContext(sc -> sc.securityContextRepository(new HttpSessionSecurityContextRepository()))
                ;
        };
        return registry
                .global(globalHttpCustomizer)
                .form(form -> form.order(20)).session(Customizer.withDefaults())
                .rest(rest -> rest.order(30)).oauth2(Customizer.withDefaults())
                .ott(ott -> ott.order(40)).oauth2(Customizer.withDefaults())
                .passkey(passkey -> passkey.order(50)).oauth2(Customizer.withDefaults())
                .mfa(mfa -> mfa
                        .primaryAuthentication(auth -> auth.formLogin(form ->
                                form.securityContextRepository(new HttpSessionSecurityContextRepository())))
                        .passkey(Customizer.withDefaults())
                        .ott(Customizer.withDefaults())
                        /*.mfaPage(page ->
                                page
                                        .ottPages("/custom/challenge/ott", "/custom/challenge/passkey")
                                        .passkeyChallengePages("/custom/challenge/passkey"))*/
                        .order(10)
                ).oauth2(Customizer.withDefaults())
                .build();
    }
}