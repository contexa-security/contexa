package io.contexa.contexaidentity.controller.example;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

/**
 * Custom MFA Controller Example
 *
 * 커스텀 MFA 페이지를 구현하는 방법을 보여주는 예시 컨트롤러입니다.
 * 이 컨트롤러는 React, Vue, Angular 등 모든 프론트엔드 프레임워크와 호환됩니다.
 *
 * DSL 설정 예시:
 * <pre>
 * .mfa(mfa -> mfa
 *     .ott(...)
 *     .passkey(...)
 *     .mfaPage(page -> page
 *         .selectFactorPage("/custom/mfa/select")
 *         .ottPages("/custom/mfa/ott-request", "/custom/mfa/ott-verify")
 *         .passkeyChallengePages("/custom/mfa/passkey")
 *     )
 * )
 * </pre>
 *
 * 주의사항:
 * 1. DefaultMfaPageGeneratingFilter가 FactorContext를 request attributes로 자동 주입합니다.
 * 2. 또는 MfaStateMachineIntegrator를 통해 직접 FactorContext를 로드할 수도 있습니다.
 * 3. 클라이언트에서는 contexa-mfa-sdk.js를 사용하여 MFA 로직을 처리합니다.
 *
 * @see io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter
 * @see io.contexa.contexaidentity.security.core.dsl.configurer.MfaPageConfigurer
 */
@Slf4j
@Controller
@RequestMapping("/custom/mfa")
@RequiredArgsConstructor
public class CustomMfaController {

    private final MfaStateMachineIntegrator stateMachineIntegrator;

    /**
     * 팩터 선택 페이지 (React 예시)
     *
     * 방법 1: DefaultMfaPageGeneratingFilter가 주입한 attributes 사용
     * 방법 2: MfaStateMachineIntegrator로 직접 로드
     */
    @GetMapping("/select")
    public String selectFactorPage(Model model, HttpServletRequest request) {
        // 방법 1: Filter가 주입한 attributes 사용 (권장)
        String mfaSessionId = (String) request.getAttribute("mfaSessionId");
        String username = (String) request.getAttribute("username");
        @SuppressWarnings("unchecked")
        List<AuthType> factors = (List<AuthType>) request.getAttribute("availableFactors");

        // 방법 2: 직접 FactorContext 로드 (필요한 경우)
        // FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        // String mfaSessionId = ctx.getMfaSessionId();
        // String username = ctx.getUsername();
        // List<AuthType> factors = ctx.getAvailableFactors();

        model.addAttribute("mfaSessionId", mfaSessionId);
        model.addAttribute("username", username);
        model.addAttribute("factors", factors);

        log.debug("Custom MFA select factor page for user: {}", username);

        // React 앱 반환 (또는 Vue, Angular)
        return "custom/react-mfa-select-factor";
    }

    /**
     * OTT 코드 요청 페이지 (Vue 예시)
     */
    @GetMapping("/ott-request")
    public String ottRequestPage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("currentState", ctx.getCurrentState().name());

        log.debug("Custom OTT request page for session: {}", ctx.getMfaSessionId());

        // Vue 앱 반환
        return "custom/vue-mfa-ott-request";
    }

    /**
     * OTT 코드 검증 페이지 (Angular 예시)
     */
    @GetMapping("/ott-verify")
    public String ottVerifyPage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("currentState", ctx.getCurrentState().name());

        log.debug("Custom OTT verify page for session: {}", ctx.getMfaSessionId());

        // Angular 앱 반환
        return "custom/angular-mfa-ott-verify";
    }

    /**
     * Passkey 인증 페이지 (Vanilla JS 예시)
     */
    @GetMapping("/passkey")
    public String passkeyChallengePage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("currentState", ctx.getCurrentState().name());

        log.debug("Custom Passkey challenge page for session: {}", ctx.getMfaSessionId());

        // Vanilla JS 앱 반환
        return "custom/vanilla-mfa-passkey";
    }

    /**
     * MFA 설정 페이지
     */
    @GetMapping("/configure")
    public String configurePage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("availableFactors", ctx.getAvailableFactors());
        model.addAttribute("completedFactors", ctx.getCompletedFactors());

        log.debug("Custom MFA configure page for user: {}", ctx.getUsername());

        return "custom/mfa-configure";
    }

    /**
     * MFA 실패 페이지
     */
    @GetMapping("/failure")
    public String failurePage(Model model, HttpServletRequest request) {
        String errorMessage = request.getParameter("error");
        model.addAttribute("errorMessage", errorMessage != null ? errorMessage : "인증에 실패했습니다.");

        log.debug("Custom MFA failure page with error: {}", errorMessage);

        return "custom/mfa-failure";
    }
}
