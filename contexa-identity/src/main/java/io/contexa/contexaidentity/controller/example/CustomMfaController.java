package io.contexa.contexaidentity.controller.example;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

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
@ConditionalOnBean(MfaStateMachineIntegrator.class)
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

        // Type-safe availableFactors 변환 (Set 또는 List 모두 처리)
        List<AuthType> factors = extractAvailableFactors(request);

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

    /**
     * Type-safe availableFactors 추출 (Set → List 변환)
     *
     * FactorContext.getAvailableFactors()는 Set<AuthType>을 반환하지만,
     * request attributes에는 Set 또는 List로 저장될 수 있습니다.
     * ClassCastException을 방지하기 위해 안전하게 변환합니다.
     */
    @SuppressWarnings("unchecked")
    private List<AuthType> extractAvailableFactors(HttpServletRequest request) {
        Object factorsObj = request.getAttribute("availableFactors");

        if (factorsObj == null) {
            log.warn("[CustomMfaController] availableFactors attribute is null");
            return Collections.emptyList();
        }

        try {
            if (factorsObj instanceof Set) {
                Set<AuthType> factorsSet = (Set<AuthType>) factorsObj;
                log.debug("[CustomMfaController] Converting Set<AuthType> to List<AuthType>, size: {}", factorsSet.size());
                return new ArrayList<>(factorsSet);
            } else if (factorsObj instanceof List) {
                List<AuthType> factorsList = (List<AuthType>) factorsObj;
                log.debug("[CustomMfaController] Using List<AuthType> directly, size: {}", factorsList.size());
                return factorsList;
            } else {
                log.error("[CustomMfaController] Unexpected availableFactors type: {}", factorsObj.getClass().getName());
                return Collections.emptyList();
            }
        } catch (ClassCastException e) {
            log.error("[CustomMfaController] Type casting failed for availableFactors", e);
            return Collections.emptyList();
        }
    }
}
