package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.security.core.AIReactiveUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Step-Up 재인증 컨트롤러
 *
 * 세션 위협 감지 시 사용자에게 재인증을 요구하는 컨트롤러입니다.
 * Grace Period 동안 사용자가 재인증을 완료하면 세션을 유지할 수 있습니다.
 *
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Controller
@RequestMapping("/auth/step-up")
@RequiredArgsConstructor
public class StepUpAuthController {

    private final RedisTemplate<String, Object> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final AIReactiveUserDetailsService aiReactiveUserDetailsService;

    @Autowired(required = false)
    private AuthenticationManager authenticationManager;

    @Value("${security.stepup.max-attempts:3}")
    private int maxAttempts;

    @Value("${security.stepup.lockout-duration:300}")
    private long lockoutDuration;

    /**
     * 재인증 페이지 표시
     */
    @GetMapping
    public String showStepUpForm(HttpServletRequest request, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return "redirect:/login";
        }

        // 세션 ID 추출
        String sessionId = extractSessionId(request);
        if (sessionId == null) {
            log.warn("[StepUpAuth] No session ID found for step-up authentication");
            return "redirect:/login";
        }

        // Grace Period 상태 확인
        String gracePeriodKey = "session:threat:grace:" + sessionId;
        Map<Object, Object> graceData = redisTemplate.opsForHash().entries(gracePeriodKey);

        if (graceData.isEmpty()) {
            // Grace Period가 없으면 일반 홈으로 리다이렉트
            model.addAttribute("info", "재인증이 필요하지 않습니다.");
            return "redirect:/";
        }

        // 남은 시간 계산
        Long ttl = redisTemplate.getExpire(gracePeriodKey);
        if (ttl != null && ttl > 0) {
            model.addAttribute("remainingTime", ttl);
            model.addAttribute("remainingMinutes", ttl / 60);
        }

        // 위협 정보 표시
        Object threatScore = graceData.get("threatScore");
        if (threatScore != null) {
            model.addAttribute("threatScore", threatScore);
        }

        model.addAttribute("username", auth.getName());
        model.addAttribute("requireStepUp", true);

        return "auth/step-up";
    }

    /**
     * 재인증 처리
     */
    @PostMapping
    public String processStepUp(
            @RequestParam String password,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated()) {
                return "redirect:/login";
            }

            String username = auth.getName();
            String sessionId = extractSessionId(request);

            if (sessionId == null) {
                redirectAttributes.addFlashAttribute("error", "세션 정보를 찾을 수 없습니다.");
                return "redirect:/auth/step-up";
            }

            // 재인증 시도 횟수 체크
            String attemptKey = "stepup:attempts:" + username;
            Integer attempts = (Integer) redisTemplate.opsForValue().get(attemptKey);

            if (attempts != null && attempts >= maxAttempts) {
                // 계정 잠금 상태
                redirectAttributes.addFlashAttribute("error",
                    "재인증 시도 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.");
                return "redirect:/auth/step-up";
            }

            // 비밀번호 검증
            UserDetails userDetails = aiReactiveUserDetailsService.loadUserByUsername(username);
            boolean passwordValid = passwordEncoder.matches(password, userDetails.getPassword());

            if (!passwordValid) {
                // 재인증 실패
                handleStepUpFailure(username, sessionId, redirectAttributes);
                return "redirect:/auth/step-up";
            }

            // 재인증 성공 처리
            handleStepUpSuccess(username, sessionId);

            // MFA가 활성화된 경우 MFA 페이지로 이동
            if (isMfaEnabled(username)) {
                return "redirect:/auth/step-up/mfa";
            }

            redirectAttributes.addFlashAttribute("success",
                "재인증이 완료되었습니다. 안전하게 계속 사용하실 수 있습니다.");

            // 원래 요청했던 페이지로 리다이렉트
            String targetUrl = (String) request.getSession().getAttribute("stepup.target.url");
            if (targetUrl != null) {
                request.getSession().removeAttribute("stepup.target.url");
                return "redirect:" + targetUrl;
            }

            return "redirect:/";

        } catch (Exception e) {
            log.error("[StepUpAuth] Step-up authentication failed", e);
            redirectAttributes.addFlashAttribute("error", "재인증 처리 중 오류가 발생했습니다.");
            return "redirect:/auth/step-up";
        }
    }

    /**
     * MFA 재인증 페이지
     */
    @GetMapping("/mfa")
    public String showMfaForm(Model model, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return "redirect:/login";
        }

        model.addAttribute("username", auth.getName());
        model.addAttribute("mfaRequired", true);

        return "auth/step-up-mfa";
    }

    /**
     * MFA 재인증 처리
     */
    @PostMapping("/mfa")
    public String processMfa(
            @RequestParam String mfaCode,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        // MFA 검증 로직 (구현 필요)
        boolean mfaValid = validateMfaCode(
            SecurityContextHolder.getContext().getAuthentication().getName(),
            mfaCode
        );

        if (!mfaValid) {
            redirectAttributes.addFlashAttribute("error", "잘못된 인증 코드입니다.");
            return "redirect:/auth/step-up/mfa";
        }

        redirectAttributes.addFlashAttribute("success",
            "MFA 재인증이 완료되었습니다.");

        return "redirect:/";
    }

    /**
     * 재인증 성공 처리
     */
    private void handleStepUpSuccess(String username, String sessionId) {
        log.info("[StepUpAuth] Step-up authentication successful - user: {}", username);

        // Grace Period 제거
        String gracePeriodKey = "session:threat:grace:" + sessionId;
        redisTemplate.delete(gracePeriodKey);

        // 지연 무효화 제거
        String delayedKey = "session:threat:delayed:" + sessionId;
        redisTemplate.delete(delayedKey);

        // 모니터링 상태로 변경
        String monitoringKey = "session:threat:monitoring:" + sessionId;
        Map<String, Object> monitoringData = new HashMap<>();
        monitoringData.put("userId", username);
        monitoringData.put("stepUpCompleted", true);
        monitoringData.put("timestamp", Instant.now().toString());

        redisTemplate.opsForHash().putAll(monitoringKey, monitoringData);
        redisTemplate.expire(monitoringKey, Duration.ofMinutes(30));

        // 재인증 시도 횟수 초기화
        String attemptKey = "stepup:attempts:" + username;
        redisTemplate.delete(attemptKey);

        // 재인증 이벤트 로깅
        logStepUpEvent(username, sessionId, "SUCCESS");
    }

    /**
     * 재인증 실패 처리
     */
    private void handleStepUpFailure(String username, String sessionId,
                                     RedirectAttributes redirectAttributes) {
        log.warn("[StepUpAuth] Step-up authentication failed - user: {}", username);

        // 재인증 시도 횟수 증가
        String attemptKey = "stepup:attempts:" + username;
        Integer attempts = (Integer) redisTemplate.opsForValue().get(attemptKey);

        if (attempts == null) {
            attempts = 0;
        }
        attempts++;

        redisTemplate.opsForValue().set(attemptKey, attempts,
            Duration.ofSeconds(lockoutDuration));

        int remainingAttempts = maxAttempts - attempts;

        if (remainingAttempts <= 0) {
            // 계정 잠금
            redirectAttributes.addFlashAttribute("error",
                "재인증 시도 횟수를 초과했습니다. 5분 후 다시 시도해 주세요.");

            // Grace Period 단축 (보안 강화)
            shortenGracePeriod(sessionId);
        } else {
            redirectAttributes.addFlashAttribute("error",
                String.format("비밀번호가 일치하지 않습니다. (남은 시도: %d회)", remainingAttempts));
        }

        // 재인증 실패 이벤트 로깅
        logStepUpEvent(username, sessionId, "FAILURE");
    }

    /**
     * Grace Period 단축
     */
    private void shortenGracePeriod(String sessionId) {
        String gracePeriodKey = "session:threat:grace:" + sessionId;
        Long currentTtl = redisTemplate.getExpire(gracePeriodKey);

        if (currentTtl != null && currentTtl > 60) {
            // 남은 시간을 1분으로 단축
            redisTemplate.expire(gracePeriodKey, Duration.ofSeconds(60));
            log.warn("[StepUpAuth] Grace period shortened due to failed attempts - sessionId: {}",
                maskSessionId(sessionId));
        }
    }

    /**
     * MFA 활성화 여부 확인
     */
    private boolean isMfaEnabled(String username) {
        // MFA 설정 확인 로직 (구현 필요)
        String mfaKey = "user:mfa:enabled:" + username;
        Boolean enabled = (Boolean) redisTemplate.opsForValue().get(mfaKey);
        return enabled != null && enabled;
    }

    /**
     * MFA 코드 검증
     */
    private boolean validateMfaCode(String username, String code) {
        // TOTP/SMS 등 MFA 검증 로직 (구현 필요)
        // 임시로 하드코딩된 값으로 테스트
        return "123456".equals(code);
    }

    /**
     * 재인증 이벤트 로깅
     */
    private void logStepUpEvent(String username, String sessionId, String result) {
        try {
            Map<String, Object> eventData = new HashMap<>();
            eventData.put("eventType", "STEP_UP_AUTH");
            eventData.put("username", username);
            eventData.put("sessionId", sessionId);
            eventData.put("result", result);
            eventData.put("timestamp", Instant.now().toString());

            // 이벤트 로깅 (감사 로그)
            String eventKey = String.format("audit:stepup:%s:%d",
                username, System.currentTimeMillis());
            redisTemplate.opsForValue().set(eventKey, eventData,
                Duration.ofDays(30));

        } catch (Exception e) {
            log.error("[StepUpAuth] Failed to log step-up event", e);
        }
    }

    /**
     * HTTP 요청에서 세션 ID 추출
     */
    private String extractSessionId(HttpServletRequest request) {
        // HttpSession에서 추출
        HttpSession session = request.getSession(false);
        if (session != null) {
            return session.getId();
        }
        return null;
    }

    /**
     * 세션 ID 마스킹
     */
    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." +
               sessionId.substring(sessionId.length() - 4);
    }
}