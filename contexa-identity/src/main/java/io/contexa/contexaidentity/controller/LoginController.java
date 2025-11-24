/*
package io.contexa.contexaidentity.controller;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

*/
/**
 * 완전 일원화된 LoginController
 * - HttpSessionContextPersistence 완전 제거
 * - MfaStateMachineIntegrator를 통한 단일 진실의 원천 사용
 * - State Machine 기반 FactorContext 조회
 *//*

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final AuthUrlProvider authUrlProvider;

    // 완전 일원화: State Machine 통합자만 사용
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    private String getContextPath(HttpServletRequest request) {
        return request.getContextPath();
    }

    */
/**
     * 완전 일원화: State Machine에서 FactorContext 로드
     * - 기존 세션 직접 접근 방식 완전 제거
     *//*

    private FactorContext loadFactorContextFromStateMachine(HttpServletRequest request) {
        try {
            return stateMachineIntegrator.loadFactorContextFromRequest(request);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from State Machine", e);
            return null;
        }
    }

    */
/**
     * 완전 일원화: MFA 세션 유효성 검증
     *//*

    private boolean isValidMfaContext(FactorContext ctx, String requiredFactorType) {
        if (ctx == null || !StringUtils.hasText(ctx.getUsername())) {
            return false;
        }

        // 터미널 상태 확인
        if (ctx.getCurrentState().isTerminal()) {
            log.warn("FactorContext is in terminal state: {}", ctx.getCurrentState());
            return false;
        }

        // 특정 팩터 타입 요구사항 확인
        if (StringUtils.hasText(requiredFactorType)) {
            AuthType currentFactor = ctx.getCurrentProcessingFactor();
            if (currentFactor == null || !requiredFactorType.equalsIgnoreCase(currentFactor.name())) {
                log.warn("Required factor type: {}, but current: {}", requiredFactorType, currentFactor);
                return false;
            }
        }

        return true;
    }

    */
/**
     * 완전 일원화: MFA 에러 리다이렉트 생성
     *//*

    private String createMfaErrorRedirect(HttpServletRequest request, String errorCode) {
        return "redirect:" + getContextPath(request) + authUrlProvider.getPrimaryLoginPage() + "?mfa_error=" + errorCode;
    }

    @GetMapping("/loginForm")
    public String loginForm(Model model, HttpServletRequest request,
                            @RequestParam(value = "error", required = false) String errorParam,
                            @RequestParam(value = "logout", required = false) String logoutParam) {
        HttpSession session = request.getSession(false);
        String errorMessage = null;
        String infoMessage = null;

        if (session != null) {
            Object exObject = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            if (exObject instanceof Exception ex) {
                errorMessage = ex.getMessage();
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            } else if (exObject != null && !(exObject instanceof String && ((String) exObject).isEmpty())) {
                errorMessage = exObject.toString();
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            }
        }

        if (StringUtils.hasText(errorParam) && errorMessage == null) {
            errorMessage = "사용자 이름 또는 비밀번호가 잘못되었습니다.";
        }

        String mfaError = request.getParameter("mfa_error");
        if (StringUtils.hasText(mfaError)) {
            errorMessage = switch (mfaError) {
                case "mfa_session_missing_or_corrupted", "mfa_session_expired" ->
                        "MFA 세션이 유효하지 않거나 만료되었습니다. 다시 로그인해주세요.";
                case "mfa_session_already_ended" ->
                        "MFA 세션이 이미 종료되었습니다. 다시 로그인해주세요.";
                case "invalid_mfa_init_context" ->
                        "MFA 시작 컨텍스트가 유효하지 않습니다.";
                case "invalid_state_for_select_factor" ->
                        "잘못된 상태에서 인증 수단 선택 페이지에 접근했습니다.";
                case "invalid_ott_request_context" ->
                        "잘못된 OTT 코드 요청 컨텍스트입니다. 인증을 다시 시작해주세요.";
                case "invalid_ott_challenge_context" ->
                        "잘못된 OTT 코드 입력 컨텍스트입니다. 인증을 다시 시작해주세요.";
                case "invalid_passkey_challenge_context" ->
                        "잘못된 Passkey 인증 요청입니다. 인증을 다시 시작해주세요.";
                case "factor_config_error_request_ui", "factor_config_error_challenge_ui" ->
                        "인증 수단 설정에 오류가 있습니다. 관리자에게 문의하세요.";
                case "invalid_challenge_page_url" ->
                        "잘못된 인증 페이지 요청입니다.";
                case "invalid_state_for_mfa_page" ->
                        "잘못된 상태에서 접근했습니다. 다시 로그인해주세요.";
                default -> "MFA 처리 중 오류가 발생했습니다: " + mfaError;
            };
        }

        String messageParam = request.getParameter("message");
        if (StringUtils.hasText(messageParam) && errorMessage == null && infoMessage == null) {
            switch (messageParam) {
                case "ott_setup_issue", "ott_setup_error":
                    errorMessage = "OTT 설정에 문제가 발생했습니다. 관리자에게 문의하세요.";
                    break;
                case "ott_generation_success_unknown_flow":
                    errorMessage = "OTT 코드 생성 후 알 수 없는 흐름으로 진행되었습니다.";
                    break;
                case "logout_success":
                    infoMessage = "성공적으로 로그아웃되었습니다.";
                    break;
                default:
                    infoMessage = messageParam;
            }
        }

        if (logoutParam != null && infoMessage == null) {
            infoMessage = "성공적으로 로그아웃되었습니다.";
        }

        model.addAttribute("errorMessage", errorMessage);
        model.addAttribute("infoMessage", infoMessage);
        model.addAttribute("pageTitle", "로그인");
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        return "login-form";
    }

    @GetMapping("/loginOtt")
    public String loginOttPage(Model model, HttpServletRequest request,
                               @RequestParam(value = "error", required = false) String error) {
        if (error != null) {
            model.addAttribute("errorMessage", "이메일 인증 코드 요청에 실패했습니다. 다시 시도해주세요.");
        }
        model.addAttribute("pageTitle", "OTT 이메일 입력");

        // 완전 일원화: State Machine에서 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        // 유효성 검증은 단순화 (단일 OTT 플로우는 엄격하지 않게)
        if (ctx != null && !StringUtils.hasText(ctx.getUsername())) {
            log.debug("Single OTT flow: FactorContext found but no username. Continuing with default flow.");
        }

        // ⭐ Phase 4: AuthUrlProvider가 우선순위 처리 (OttOptions > properties > defaults)
        String tokenGeneratingUrl = authUrlProvider.getOttCodeGeneration();

        model.addAttribute("ottCodeRequestApiUrl", getContextPath(request) + tokenGeneratingUrl);
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        return "login-ott";
    }

    @GetMapping("/ott/sent")
    public String ottSentPage(@RequestParam String email,
                              @RequestParam(required = false) String type,
                              @RequestParam(required = false) String flow,
                              Model model, HttpServletRequest request) {
        model.addAttribute("email", email);
        model.addAttribute("pageTitle", "인증 메일 발송 완료");

        String nextChallengeUrl = null;
        String nextChallengeMessage = null;
        String contextPath = getContextPath(request);

        if ("code_sent".equals(type)) {
            model.addAttribute("messageType", "code_sent");
            if ("mfa".equalsIgnoreCase(flow)) {
                nextChallengeUrl = contextPath + authUrlProvider.getOttChallengeUi();
                nextChallengeMessage = "MFA 인증 코드 입력 페이지로 이동하여 코드를 입력해주세요.";
            } else { // 단일 OTT
                String singleOttVerifyPageUrl = authUrlProvider.getSingleOttChallenge();
                nextChallengeUrl = UriComponentsBuilder.fromPath(contextPath + singleOttVerifyPageUrl)
                        .queryParam("email", email)
                        .toUriString();
                nextChallengeMessage = "인증 코드 입력 페이지로 이동하여 코드를 입력해주세요.";
            }
            model.addAttribute("nextChallengeMessage", nextChallengeMessage);
            model.addAttribute("nextChallengeUrl", nextChallengeUrl);
        } else if ("magic_link_sent".equals(type)) {
            model.addAttribute("messageType", "magic_link_sent");
            model.addAttribute("loginPageUrl", contextPath + authUrlProvider.getPrimaryLoginPage());
        } else {
            model.addAttribute("messageType", "unknown_sent_type");
            model.addAttribute("nextChallengeMessage", "이메일을 확인해주세요.");
        }

        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용
        return "ott-sent";
    }

    @GetMapping("/loginOttVerifyCode")
    public String loginOttVerifyCodePage(@RequestParam String email, Model model, HttpServletRequest request,
                                         @RequestParam(required = false) String error) {
        model.addAttribute("emailForVerification", email);
        model.addAttribute("pageTitle", "OTT 코드 검증");

        String processingUrl = authUrlProvider.getOttLoginProcessing();
        String resendUrl = authUrlProvider.getOttRequestCodeUi();

        // 완전 일원화: State Machine에서 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        if (!isValidMfaContext(ctx, null)) {
            log.warn("Single OTT Verify: Invalid FactorContext. Redirecting to login.");
            return createMfaErrorRedirect(request, "mfa_session_expired");
        }

        // P0.3: AuthUrlProvider가 이미 우선순위 로직 처리 (OttOptions > MfaPageConfig > properties)
        // 중복 제거 - AuthUrlProvider에서 이미 처리함

        model.addAttribute("ottProcessingUrl", getContextPath(request) + processingUrl);
        model.addAttribute("singleOttResendUrl", getContextPath(request) + resendUrl);
        model.addAttribute("isMfaFlow", false);

        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", "인증 코드가 잘못되었거나 만료되었습니다. 다시 시도해주세요.");
        }

        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용
        return "login-ott-verify-code";
    }

    @GetMapping("/loginPasskey")
    public String loginPasskeyPage(Model model, HttpServletRequest request) {
        model.addAttribute("pageTitle", "Passkey 로그인");
        String contextPath = getContextPath(request);
        model.addAttribute("passkeyAssertionOptionsUrl", contextPath + authUrlProvider.getPasskeyAssertionOptions());
        model.addAttribute("passkeyAssertionProcessUrl", contextPath + authUrlProvider.getPasskeyLoginProcessing());
        model.addAttribute("passkeyRegistrationOptionsUrl", contextPath + authUrlProvider.getPasskeyRegistrationOptions());
        model.addAttribute("passkeyRegistrationProcessUrl", contextPath + authUrlProvider.getPasskeyRegistrationProcessing());
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용
        return "login-passkey";
    }

    @GetMapping("/mfa/select-factor")
    public String mfaSelectFactorPage(Model model, HttpServletRequest request,
                                      @RequestParam(required = false) String error) {
        // 완전 일원화: State Machine에서 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        if (!isValidMfaContext(ctx, null)) {
            log.warn("MFA Select Factor UI: Invalid FactorContext. State: {}. Redirecting to login.",
                    ctx != null ? ctx.getCurrentState() : "null");
            return createMfaErrorRedirect(request, "mfa_session_expired");
        }

        // 상태 검증 - AWAITING_FACTOR_SELECTION 상태여야 함
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("MFA Select Factor UI: Invalid state for factor selection: {}. Expected: AWAITING_FACTOR_SELECTION",
                    ctx.getCurrentState());
            return createMfaErrorRedirect(request, "invalid_state_for_select_factor");
        }

        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("currentState", ctx.getCurrentState().name());
        model.addAttribute("availableFactors", ctx.getAvailableFactors());

        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", "인증 수단 선택 중 오류: " + error);
        }

        model.addAttribute("pageTitle", "MFA 인증 수단 선택");
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        return "login-mfa-select-factor";
    }

    @GetMapping("/mfa/ott/request-code-ui")
    public String mfaOttRequestCodeUiPage(Model model, HttpServletRequest request) {
        // 완전 일원화: State Machine에서 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        if (!isValidMfaContext(ctx, "OTT") || !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("MFA OTT Request Code UI: Invalid FactorContext, not an OTT factor, or currentStepId missing. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authUrlProvider.getMfaSelectFactor() + "?error=invalid_ott_request_context";
        }

        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("currentState", ctx.getCurrentState().name());
        model.addAttribute("pageTitle", "MFA - 이메일 인증 코드 요청");

        // P0.3: AuthUrlProvider가 이미 우선순위 로직 처리 (OttOptions > MfaPageConfig > properties)
        String tokenGeneratingUrl = authUrlProvider.getOttCodeGeneration();

        model.addAttribute("mfaOttCodeRequestFormActionUrl", getContextPath(request) + tokenGeneratingUrl);
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        return "login-mfa-ott-request-code";
    }

    @GetMapping("/mfa/challenge/ott")
    public String mfaVerifyOttPage(Model model, HttpServletRequest request,
                                   @RequestParam(value = "resend_success", required = false) String resendSuccess) {
        // 완전 일원화: State Machine에서 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        if (!isValidMfaContext(ctx, "OTT") || !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("MFA OTT Challenge UI: Invalid FactorContext, not an OTT factor, or currentStepId missing. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authUrlProvider.getMfaSelectFactor() + "?error=invalid_ott_challenge_context";
        }

        model.addAttribute("usernameForDisplay", ctx.getUsername());
        model.addAttribute("emailForVerification", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("currentState", ctx.getCurrentState().name());
        model.addAttribute("pageTitle", "MFA - 코드 입력");

        // P0.3: AuthUrlProvider가 이미 우선순위 로직 처리 (OttOptions > MfaPageConfig > properties)
        String loginProcessingUrl = authUrlProvider.getOttLoginProcessing();

        model.addAttribute("mfaOttProcessingUrl", getContextPath(request) + loginProcessingUrl);
        model.addAttribute("mfaResendOttUrl", getContextPath(request) + authUrlProvider.getMfaRequestOttCode());

        if (resendSuccess != null) {
            model.addAttribute("successMessage", "인증 코드가 재전송되었습니다.");
        }

        String errorParam = request.getParameter("mfa_error");
        if (!StringUtils.hasText(errorParam)) {
            errorParam = request.getParameter("error");
        }
        if (StringUtils.hasText(errorParam)) {
            model.addAttribute("errorMessage", "인증 코드가 잘못되었거나 만료되었습니다.");
        }

        model.addAttribute("isMfaFlow", true);
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        return "login-mfa-verify-ott";
    }

    @GetMapping("/mfa/challenge/passkey")
    public String mfaVerifyPasskeyPage(Model model, HttpServletRequest request) {
        // 완전 일원화: State Machine에서 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        if (!isValidMfaContext(ctx, "PASSKEY")) {
            log.warn("MFA Passkey Challenge UI: Invalid FactorContext or not a Passkey factor. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authUrlProvider.getMfaSelectFactor() + "?error=invalid_passkey_challenge_context";
        }

        model.addAttribute("usernameForDisplay", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("currentState", ctx.getCurrentState().name());
        model.addAttribute("pageTitle", "MFA - Passkey 인증");

        model.addAttribute("mfaPasskeyAssertionOptionsUrl", getContextPath(request) + authUrlProvider.getPasskeyAssertionOptions());
        String loginProcessingUrl = authUrlProvider.getPasskeyLoginProcessing();
        model.addAttribute("mfaPasskeyProcessingUrl", getContextPath(request) + loginProcessingUrl);
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        return "login-mfa-verify-passkey";
    }

    @GetMapping("/mfa/failure")
    public String mfaFailurePage(@RequestParam(required = false) String error,
                                 @RequestParam(required = false) String message,
                                 Model model, HttpServletRequest request) {
        String errorMessageToDisplay = "MFA 인증에 실패했습니다. 다시 시도해주세요.";

        if (StringUtils.hasText(message)) {
            errorMessageToDisplay = message;
        } else if (StringUtils.hasText(error)) {
            errorMessageToDisplay = switch (error) {
                case "mfa_max_attempts_exceeded_ott" ->
                        "OTT 인증 최대 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.";
                case "mfa_locked_ott" ->
                        "OTT 인증이 잠겼습니다. 관리자에게 문의하세요.";
                case "mfa_factor_verification_failed" ->
                        "제공된 인증 정보가 올바르지 않습니다.";
                default -> "MFA 인증 중 오류 발생: " + error;
            };
        }

        model.addAttribute("errorMessage", errorMessageToDisplay);
        model.addAttribute("pageTitle", "MFA 인증 실패");
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용

        // 세션 정리 (실패 시 State Machine 정리)
        try {
            stateMachineIntegrator.cleanupSession(request);
            log.debug("State Machine cleaned up after MFA failure");
        } catch (Exception e) {
            log.warn("Failed to cleanup State Machine after MFA failure", e);
        }

        return "mfa-failure";
    }

    @GetMapping("/logout")
    public String logoutPage(Model model) {
        model.addAttribute("pageTitle", "로그아웃");
        model.addAttribute("storageType", "UNIFIED_STATE_MACHINE"); // 디버깅용
        return "logout";
    }

    // P0.3: 유틸리티 메서드 제거 - AuthUrlProvider가 우선순위 로직을 담당하므로 불필요
}
*/
