package io.contexa.contexaidentity.security.config;/*
package io.contexa.contexaidentity.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.contexa.contexaidentity.security.handler.MfaFactorProcessingSuccessHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class PlatformSecurityConfig2 {

    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;
    private final ObjectMapper objectMapper;
    private final AuthResponseWriter authResponseWriter;
    private final EmailOneTimeTokenService emailOneTimeTokenService; // 주입 유지 (단일 OTT 및 MFA API에서 사용)

    private final MfaFactorProcessingSuccessHandler mfaFactorProcessingSuccessHandler;
    private final UnifiedAuthenticationFailureHandler unifiedAuthenticationFailureHandler;
    private final UnifiedAuthenticationSuccessHandler unifiedAuthenticationSuccessHandler; // 최종 성공 시


    // 단일 인증 실패 시 사용될 수 있는 기본 핸들러
    private AuthenticationFailureHandler singleAuthSimpleFailureHandler(String failureUrl) {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }

    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {
        log.info("Configuring Platform Security DSL with refined MFA OTT flow...");

        String rpId = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");

        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
            // ... (기존 globalHttpCustomizer 로직은 거의 동일하게 유지: csrf, authorizeHttpRequests, headers, sessionManagement, exceptionHandling, logout 등)
            try {
                http
                        .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers( // 기존 permitAll 경로 유지 + OTT generate/sent 추가
                                        "/css/**", "/js/**", "/images/**", "/favicon.ico",
                                        "/", "/authMode",
                                        "/loginForm", "/register",
                                        "/ott/generate", "/ott/sent", // 단일 OTT 코드 생성 요청(GET/POST) 및 성공 페이지
                                        "/loginOtt",                  // 단일 OTT 코드 검증 링크 (GET)
                                        "/loginPasskey",
                                        "/mfa/select-factor", "/mfa/challenge/ott", "/mfa/challenge/passkey", "/mfa/failure",
                                        "/api/register",
                                        "/api/auth/login", "/api/auth/refresh",
                                        // "/api/ott/generate", // 단일 OTT 코드 생성은 Spring Security Filter가 처리하도록 변경
                                        "/webauthn/registration/options", "/webauthn/registration/verify",
                                        "/webauthn/assertion/options", "/webauthn/assertion/verify",
                                        "/api/mfa/**" // MFA 관련 API 전체 허용 (MfaApiController가 내부적으로 접근 제어)
                                ).permitAll()
                                .requestMatchers("/users", "/api/users").hasRole("USER")
                                .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN")
                                .anyRequest().authenticated()
                        )
                        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                        .sessionManagement(session -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // JWT
                        )
                        .exceptionHandling(e -> e
                                .authenticationEntryPoint(new TokenAuthenticationEntryPoint(objectMapper))
                        )
                        .logout(logout -> logout
                                .logoutUrl("/api/auth/logout")
                                .addLogoutHandler(applicationContext.getBean("jwtLogoutHandler", LogoutHandler.class))
                                .logoutSuccessHandler((request, response, authentication) -> {
                                    response.setStatus(HttpServletResponse.SC_OK);
                                    response.setContentType("application/json;charset=UTF-8");
                                    objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                                })
                                .invalidateHttpSession(false)
                                .clearAuthentication(true)
                        );
            } catch (Exception e) {
                throw new RuntimeException("Failed to apply global HttpSecurity customizer", e);
            }
        };


        return registry
                .global(globalHttpCustomizer)

                // --- 단일 인증 방식들 ---
                .form(form -> form // 예: "form_flow"
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login")
                        .successHandler(unifiedAuthenticationSuccessHandler) // 성공 시 JWT 발급 (MFA 불필요 시)
                        .failureHandler(unifiedAuthenticationFailureHandler)  // 통합 실패 핸들러 사용
                        .permitAll()
                        .order(100)
                ).jwt(Customizer.withDefaults())

                .ott(ott -> ott // 예: "ott_flow_1"
                        .tokenService(emailOneTimeTokenService) // 플랫폼의 EmailOneTimeTokenService 사용
                        // 이 URL은 Spring Security의 GenerateOneTimeTokenFilter가 처리 (POST로 이메일 받아 코드 생성/발송)
                        .tokenGeneratingUrl("/ott/generate")
                        // 이 URL은 Spring Security의 AuthenticationFilter(OTT용)가 처리 (GET/POST로 코드 검증)
                        .loginProcessingUrl("/login/ott")
                        // MagicLinkHandler (OneTimeTokenGenerationSuccessHandler)가 /ott/sent?email=... 로 리다이렉션
                        .tokenGenerationSuccessHandler(applicationContext.getBean("magicLinkHandler", OneTimeTokenGenerationSuccessHandler.class))
                        .successHandler(unifiedAuthenticationSuccessHandler) // 최종 성공 시 JWT 발급
                        .failureHandler(unifiedAuthenticationFailureHandler)  // 통합 실패 핸들러 사용
                        .order(110)
                ).jwt(Customizer.withDefaults())

                .passkey(passkey -> passkey // 예: "passkey_flow_1"
                        .rpId(rpId)
                        .rpName("Spring Security 6x IDP")
                        .assertionOptionsEndpoint("/webauthn/assertion/options") // Spring Security 기본
                        .loginProcessingUrl("/login/webauthn")             // Spring Security 기본
                        .successHandler(unifiedAuthenticationSuccessHandler)
                        .failureHandler(unifiedAuthenticationFailureHandler)
                        .order(120)
                ).jwt(Customizer.withDefaults())

                // --- MFA 플로우 설정 ---
                .mfa(mfa -> mfa // typeName: "mfa"
                        .primaryAuthentication(primaryAuth -> primaryAuth
                                .restLogin(rest -> rest // stepId: "mfa:rest:0"
                                        .loginProcessingUrl("/api/auth/login")
                                        .successHandler(unifiedAuthenticationSuccessHandler) // 1차 인증 성공 및 MFA 시작
                                        .failureHandler(unifiedAuthenticationFailureHandler)
                                )
                        )
                        .ott(ottFactor -> ottFactor // stepId: "mfa:ott:1" (또는 다음 order)
                                .tokenService(emailOneTimeTokenService) // 코드 검증에 사용될 서비스
                                .tokenGeneratingUrl("/mfa/ott/generate")
                                // 코드 생성은 /api/mfa/request-ott-code (MfaApiController)를 통해 요청.
                                // 이 URL은 MfaStepFilterWrapper가 감지하여 Spring Security AuthenticationFilter(OTT용)로 위임 (코드 검증)
                                .loginProcessingUrl("/login/mfa-ott") // 클라이언트 JS(mfa-verify-ott.js)가 이 URL로 POST
                                .successHandler(mfaFactorProcessingSuccessHandler) // OTT Factor 성공 시 다음 단계 또는 최종 완료
                                .failureHandler(unifiedAuthenticationFailureHandler)
                        )
                        .passkey(passkeyFactor -> passkeyFactor // stepId: "mfa:passkey:2" (또는 다음 order)
                                .rpId(rpId)
                                .rpName("Spring Security 6x IDP MFA")
                                // Assertion Options 요청은 클라이언트 JS(mfa-verify-passkey.js)가 /api/mfa/assertion/options (MfaApiController) 호출
                                .assertionOptionsEndpoint("/api/mfa/assertion/options") // 클라이언트가 호출할 API
                                // 이 URL은 MfaStepFilterWrapper가 감지하여 Spring Security WebAuthnAuthenticationFilter로 위임 (Assertion 검증)
                                .loginProcessingUrl("/login/mfa-passkey") // 클라이언트 JS가 이 URL로 POST
                                .successHandler(mfaFactorProcessingSuccessHandler)
                                .failureHandler(unifiedAuthenticationFailureHandler)
                        )
                        .finalSuccessHandler(unifiedAuthenticationSuccessHandler) // 모든 MFA Factor 완료 후
                        .policyProvider(applicationContext.getBean(MfaPolicyProvider.class))
                        .mfaFailureHandler(unifiedAuthenticationFailureHandler) // MFA 플로우 전역 실패
                        .order(20)
                ).jwt(Customizer.withDefaults())

                .build();
    }
}
*/
