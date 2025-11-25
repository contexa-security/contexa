package io.contexa.springbootstartercontexa;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.filter.SecurityEventPublishingFilter;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaiam.security.core.AIReactiveSecurityContextRepository;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
//@EnableRedisHttpSession
public class IAMSecurityConfig {
    private final CustomDynamicAuthorizationManager customDynamicAuthorizationManager;
    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final AIReactiveSecurityContextRepository aiReactiveSecurityContextRepository;
    private final HCADFilter hcadFilter;
    private final SecurityEventPublishingFilter securityEventPublishingFilter;
    private final ApplicationEventPublisher eventPublisher;
    private final UserIdentificationService userIdentificationService;

    private final HCADAnalysisService hcadAnalysisService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http/*, AsepConfigurer asepConfigurer*/) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .anyRequest().access(customDynamicAuthorizationManager));
        http.formLogin(form -> form.loginPage("/login")
                .successHandler((request, response, authentication) -> {
                    UserDto userDto = (UserDto) authentication.getPrincipal();

                    // 유사도 재계산
                    HCADAnalysisResult result = hcadAnalysisService.analyze(request, authentication);

                    log.info("[MySecurityConfig] 로그인 성공: userId={}, similarity={}, trust={}",
                        userDto.getUsername(),
                        String.format("%.3f", result.getSimilarityScore()),
                        String.format("%.3f", result.getTrustScore()));

                    // 기준선 업데이트 (정상 로그인 패턴 학습)
                    hcadAnalysisService.updateBaselineIfNeeded(result);

                    AuthenticationSuccessEvent.AuthenticationSuccessEventBuilder builder =
                            AuthenticationSuccessEvent.builder()
                                    .eventId(java.util.UUID.randomUUID().toString())
                                    .userId(userDto.getUsername())  // Zero Trust를 위한 사용자 식별자 (username)
                                    .username(userDto.getUsername())
                                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                                    .eventTimestamp(java.time.LocalDateTime.now())
                                    .sourceIp(extractClientIp(request))
                                    .userAgent(request.getHeader("User-Agent"))
                                    .hcadSimilarityScore(result.getSimilarityScore())  // 재계산된 값 사용
                                    .trustScore(result.getTrustScore());

                    AuthenticationSuccessEvent event = builder.build();

                    // ===== 메트릭 수집 =====
                    long startTime = System.nanoTime();
                    eventPublisher.publishEvent(event);
                    long duration = System.nanoTime() - startTime;

                    request.setAttribute("security.event.published", true);
                    response.sendRedirect("/admin");

                }).failureHandler((request, response, exception) -> {
                    String username = userIdentificationService.extractUserId(request, null, exception);

                    // 로그인 실패 시에도 서비스 사용 (일관성 유지)
                    // 현재 Authentication은 null 또는 anonymousUser
                    Authentication currentAuth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                    HCADAnalysisResult result = hcadAnalysisService.analyze(request, currentAuth);

                    log.warn("[MySecurityConfig] 로그인 실패: username={}, similarity={}, reason={}",
                        username,
                        String.format("%.3f", result.getSimilarityScore()),
                        exception.getMessage());

                    AuthenticationFailureEvent.AuthenticationFailureEventBuilder builder =
                            AuthenticationFailureEvent.builder()
                                    .eventId(java.util.UUID.randomUUID().toString())
                                    .userId(username)
                                    .username(username)
                                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                                    .eventTimestamp(java.time.LocalDateTime.now())
                                    .sourceIp(extractClientIp(request))
                                    .userAgent(request.getHeader("User-Agent"))
                                    .failureReason(exception.getMessage())
                                    .exceptionClass(exception.getClass().getName())
                                    .exceptionMessage(exception.getMessage())
                                    .hcadSimilarityScore(result.getSimilarityScore());

                    AuthenticationFailureEvent event = builder.build();

                    // ===== 메트릭 수집 =====
                    long startTime = System.nanoTime();
                    eventPublisher.publishEvent(event);
                    long duration = System.nanoTime() - startTime;

                    // 이벤트 발행 플래그 설정 (SecurityEventPublishingFilter에서 중복 방지)
                    request.setAttribute("security.event.published", true);
                })
        );
        http.authenticationProvider(customAuthenticationProvider);
        http.csrf(AbstractHttpConfigurer::disable);
        
        // AI-Native Security Context Repository 설정 (세션 무효화 처리)
        if (aiReactiveSecurityContextRepository != null) {
            http.securityContext(context -> context
                    .securityContextRepository(aiReactiveSecurityContextRepository));
        }

        // HCAD 필터 추가 (실시간 이상 탐지 및 차단)
        if (hcadFilter != null) {
            http.addFilterAfter(hcadFilter, SecurityContextHolderFilter.class);
            http.addFilterAfter(securityEventPublishingFilter, HCADFilter.class);
//            http.addFilterAfter(asepConfigurer.asepFilter(), HCADFilter.class);
        } else {
//            http.addFilterAfter(asepConfigurer.asepFilter(), SecurityContextHolderFilter.class);
        }
        return http.build();
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        return new RoleHierarchyImpl();
    }

}
