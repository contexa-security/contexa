package io.contexa.contexaiam.aiam.web;

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
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;


@Slf4j
@RequestMapping("/auth/step-up")
@RequiredArgsConstructor
public class StepUpAuthController {

    private final RedisTemplate<String, Object> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    @Autowired(required = false)
    private AuthenticationManager authenticationManager;

    @Value("${security.stepup.max-attempts:3}")
    private int maxAttempts;

    @Value("${security.stepup.lockout-duration:300}")
    private long lockoutDuration;

    
    @GetMapping
    public String showStepUpForm(HttpServletRequest request, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return "redirect:/login";
        }

        
        String sessionId = extractSessionId(request);
        if (sessionId == null) {
            log.warn("[StepUpAuth] No session ID found for step-up authentication");
            return "redirect:/login";
        }

        
        String gracePeriodKey = "session:threat:grace:" + sessionId;
        Map<Object, Object> graceData = redisTemplate.opsForHash().entries(gracePeriodKey);

        if (graceData.isEmpty()) {
            
            model.addAttribute("info", "재인증이 필요하지 않습니다.");
            return "redirect:/";
        }

        
        Long ttl = redisTemplate.getExpire(gracePeriodKey);
        if (ttl != null && ttl > 0) {
            model.addAttribute("remainingTime", ttl);
            model.addAttribute("remainingMinutes", ttl / 60);
        }

        
        Object threatScore = graceData.get("threatScore");
        if (threatScore != null) {
            model.addAttribute("threatScore", threatScore);
        }

        model.addAttribute("username", auth.getName());
        model.addAttribute("requireStepUp", true);

        return "auth/step-up";
    }

    
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

            
            String attemptKey = "stepup:attempts:" + username;
            Integer attempts = (Integer) redisTemplate.opsForValue().get(attemptKey);

            if (attempts != null && attempts >= maxAttempts) {
                
                redirectAttributes.addFlashAttribute("error",
                    "재인증 시도 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.");
                return "redirect:/auth/step-up";
            }

            
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            boolean passwordValid = passwordEncoder.matches(password, userDetails.getPassword());

            if (!passwordValid) {
                
                handleStepUpFailure(username, sessionId, redirectAttributes);
                return "redirect:/auth/step-up";
            }

            
            handleStepUpSuccess(username, sessionId);

            
            if (isMfaEnabled(username)) {
                return "redirect:/auth/step-up/mfa";
            }

            redirectAttributes.addFlashAttribute("success",
                "재인증이 완료되었습니다. 안전하게 계속 사용하실 수 있습니다.");

            
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

    
    @PostMapping("/mfa")
    public String processMfa(
            @RequestParam String mfaCode,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        
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

    
    private void handleStepUpSuccess(String username, String sessionId) {
        log.info("[StepUpAuth] Step-up authentication successful - user: {}", username);

        
        String gracePeriodKey = "session:threat:grace:" + sessionId;
        redisTemplate.delete(gracePeriodKey);

        
        String delayedKey = "session:threat:delayed:" + sessionId;
        redisTemplate.delete(delayedKey);

        
        String monitoringKey = "session:threat:monitoring:" + sessionId;
        Map<String, Object> monitoringData = new HashMap<>();
        monitoringData.put("userId", username);
        monitoringData.put("stepUpCompleted", true);
        monitoringData.put("timestamp", Instant.now().toString());

        redisTemplate.opsForHash().putAll(monitoringKey, monitoringData);
        redisTemplate.expire(monitoringKey, Duration.ofMinutes(30));

        
        String attemptKey = "stepup:attempts:" + username;
        redisTemplate.delete(attemptKey);

        
        logStepUpEvent(username, sessionId, "SUCCESS");
    }

    
    private void handleStepUpFailure(String username, String sessionId,
                                     RedirectAttributes redirectAttributes) {
        log.warn("[StepUpAuth] Step-up authentication failed - user: {}", username);

        
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
            
            redirectAttributes.addFlashAttribute("error",
                "재인증 시도 횟수를 초과했습니다. 5분 후 다시 시도해 주세요.");

            
            shortenGracePeriod(sessionId);
        } else {
            redirectAttributes.addFlashAttribute("error",
                String.format("비밀번호가 일치하지 않습니다. (남은 시도: %d회)", remainingAttempts));
        }

        
        logStepUpEvent(username, sessionId, "FAILURE");
    }

    
    private void shortenGracePeriod(String sessionId) {
        String gracePeriodKey = "session:threat:grace:" + sessionId;
        Long currentTtl = redisTemplate.getExpire(gracePeriodKey);

        if (currentTtl != null && currentTtl > 60) {
            
            redisTemplate.expire(gracePeriodKey, Duration.ofSeconds(60));
            log.warn("[StepUpAuth] Grace period shortened due to failed attempts - sessionId: {}",
                maskSessionId(sessionId));
        }
    }

    
    private boolean isMfaEnabled(String username) {
        
        String mfaKey = "user:mfa:enabled:" + username;
        Boolean enabled = (Boolean) redisTemplate.opsForValue().get(mfaKey);
        return enabled != null && enabled;
    }

    
    private boolean validateMfaCode(String username, String code) {
        
        
        return "123456".equals(code);
    }

    
    private void logStepUpEvent(String username, String sessionId, String result) {
        try {
            Map<String, Object> eventData = new HashMap<>();
            eventData.put("eventType", "STEP_UP_AUTH");
            eventData.put("username", username);
            eventData.put("sessionId", sessionId);
            eventData.put("result", result);
            eventData.put("timestamp", Instant.now().toString());

            
            String eventKey = String.format("audit:stepup:%s:%d",
                username, System.currentTimeMillis());
            redisTemplate.opsForValue().set(eventKey, eventData,
                Duration.ofDays(30));

        } catch (Exception e) {
            log.error("[StepUpAuth] Failed to log step-up event", e);
        }
    }

    
    private String extractSessionId(HttpServletRequest request) {
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            return session.getId();
        }
        return null;
    }

    
    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." +
               sessionId.substring(sessionId.length() - 4);
    }
}