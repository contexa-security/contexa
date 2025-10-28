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
                                    "/authMode",
//                                    "/", "/authMode","/home",
                                    "/loginForm", "/register",
                                    "/loginOtt", "/ott/sent",
                                    "/loginPasskey",
                                    "/mfa/select-factor","/mfa/ott/request-code-ui", "/mfa/challenge/ott", "/mfa/challenge/passkey", "/mfa/failure",
                                    "/api/register",
                                    "/api/auth/login", "/api/auth/refresh",
                                    "/api/ott/generate",
                                    "/webauthn/registration/options", "/webauthn/registration/verify",
                                    "/webauthn/assertion/options", "/webauthn/assertion/verify",
                                    "/api/mfa/select-factor", "/api/mfa/request-ott-code", "/api/mfa/assertion/options"
                            ).permitAll()
                            .requestMatchers("/users", "/api/users").hasRole("USER")
                            .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated()
                    )
                    .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                    .sessionManagement(session -> session
                                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    )
                    // ⭐ MfaAuthenticationEntryPoint는 MfaPageGeneratingConfigurer에서 자동 등록됨
                    // DSL 설정(AuthenticationFlowConfig)에서 생성된 EntryPoint가 사용됨
                    // .exceptionHandling(e -> e.authenticationEntryPoint(...)) // 제거됨
                    .logout(logout -> logout
//                            .logoutUrl("/api/auth/logout")
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
                        .primaryAuthentication(primaryAuth -> primaryAuth
                                .restLogin(rest -> rest
//                                    .loginProcessingUrl("/api/auth/login")
                                    .rawHttp(http -> http.authenticationProvider(restAuthenticationProvider))
                                    .successHandler(new PlatformAuthenticationSuccessHandler() {
                                        @Override
                                        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication, TokenTransportResult result) throws IOException, ServletException {
                                            System.out.println("onAuthenticationFailure: " + result);
                                        }
                                    })
                                    .failureHandler(new PlatformAuthenticationFailureHandler() {
                                        @Override
                                        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception, FactorContext factorContext, PlatformAuthenticationFailureHandler.FailureType failureType, Map<String, Object> errorDetails) throws IOException, ServletException {
                                            System.out.println("onAuthenticationFailure: " + exception.getMessage());
                                        }
                                    })
                                )
                        )
                        .ott(ott -> ott
//                                .loginProcessingUrl("/login/mfa-ott")
                                .rawHttp(http -> http.oneTimeTokenLogin(
                                        ott1 -> ott1
                                        .authenticationConverter(new OneTimeTokenAuthenticationConverter(){
                                            @Override
                                            public Authentication convert(HttpServletRequest request) {
                                                String token = request.getParameter("token");
                                                if (!StringUtils.hasText(token)) {
                                                                                                        return null;
                                                }
                                                return OneTimeTokenAuthenticationToken.unauthenticated(request.getParameter("username"),token);
                                            }
                                        })))
                        )
                        .passkey(passkeyFactor -> passkeyFactor
                                .rpId("rpId")
                                .rpName("Spring Security 6x IDP MFA")
                        )
                        /*.mfaPage(page -> page
                                .selectFactorPage("/mfa/select-factor")
                                .ottPages("/mfa/ott/request-code-ui", "/mfa/challenge/ott")
                                .passkeyChallengePages("/mfa/challenge/passkey")
                                .failurePageUrl("/mfa/failure")
                        )*/
                        .order(20)
                ).oauth2(Customizer.withDefaults())
                .build();
    }/**/
}