package io.contexa.springbootstartercontexa;

import io.contexa.contexacore.security.AIReactiveSecurityContextRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class PlatformSecurityConfig {

    private final CustomDynamicAuthorizationManager customDynamicAuthorizationManager;
    private final AIReactiveSecurityContextRepository aiReactiveSecurityContextRepository;

    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {
        log.info("Configuring Platform Security DSL...");

        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
            http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers(
                                    "/css/**", "/js/**", "/images/**", "/favicon.ico",
                                    "/test/security",
                                    "/", "/authMode","/home",
                                    "/loginForm", "/register","/login","/admin/login",
                                    "/loginOtt", "/ott/sent",
                                    "/loginPasskey","/login/mfa-ott",
                                    "/mfa/select-factor","/mfa/ott/request-code-ui", "/mfa/challenge/ott",
                                    "/mfa/challenge/passkey", "/mfa/failure","/mfa/ott/generate-code","/mfa/ott/code-sent",
                                    "/api/register",
                                    "/api/login", "/api/refresh",
                                    "/api/ott/generate",
                                    "/webauthn/register/options", "/webauthn/register","/login/mfa-webauthn",
                                    "/webauthn/authenticate/options", "/login/webauthn",
                                    "/api/mfa/select-factor", "/api/mfa/request-ott-code", "/api/mfa/config",
                                    "/sse"
                            ).permitAll()
                            .anyRequest().access(customDynamicAuthorizationManager)
                    )
                    .securityContext(sc -> sc.securityContextRepository(aiReactiveSecurityContextRepository))
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
            ;
        };
        return registry
                .global(globalHttpCustomizer)
                .form(form -> form.order(10)
                        .loginPage("/admin/login")
                        .defaultSuccessUrl("/admin"))
                .oauth2(Customizer.withDefaults())
//                .rest(rest -> rest.order(20)).session(Customizer.withDefaults())
//                .ott(ott -> ott.order(30)).session(Customizer.withDefaults())
//                .passkey(passkey -> passkey.order(40)).session(Customizer.withDefaults())

                /*.form(form -> form.order(50)).oauth2(Customizer.withDefaults())
                .rest(rest -> rest.order(60)).oauth2(Customizer.withDefaults())
                .ott(ott -> ott.order(70)).oauth2(Customizer.withDefaults())
                .passkey(passkey -> passkey.order(80)).oauth2(Customizer.withDefaults())*/
                /*.mfa(mfa -> mfa
                        .primaryAuthentication(auth -> auth.formLogin(form ->
                                form.defaultSuccessUrl("/test/security").
                                        defaultSuccessUrl("/test/security", true).
                                        securityContextRepository(new HttpSessionSecurityContextRepository())))
//                        .primaryAuthentication(auth -> auth.restLogin(Customizer.withDefaults()))
                        .passkey(Customizer.withDefaults())
                        .ott(Customizer.withDefaults())
                        *//*.mfaPage(page ->
                                page
                                        .ottPages("/custom/challenge/ott", "/custom/challenge/passkey")
                                        .passkeyChallengePages("/custom/challenge/passkey"))*//*
                        .order(60)
                ).session(Customizer.withDefaults())*/
                .build();
    }
}