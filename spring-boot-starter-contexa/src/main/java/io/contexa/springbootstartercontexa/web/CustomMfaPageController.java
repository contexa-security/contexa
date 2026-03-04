package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.HtmlUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class CustomMfaPageController {

    private final AuthUrlProvider authUrlProvider;
    private final MfaStateMachineIntegrator mfaStateMachineIntegrator;
    private final MfaSessionRepository mfaSessionRepository;
    private final AuthContextProperties authContextProperties;

    @GetMapping("/customLogin")
    public String customLoginPage(HttpServletRequest request, Model model) {
        addCommonModelAttributes(request, model);
        model.addAttribute("primaryFormLoginProcessingUrl", authUrlProvider.getPrimaryFormLoginProcessing());
        model.addAttribute("selectFactorUrl", authUrlProvider.getMfaSelectFactor());
        model.addAttribute("error", request.getParameter("error"));
        model.addAttribute("logout", request.getParameter("logout"));
        return "custom/custom-login";
    }

    @GetMapping("/custom/mfa/ott/request-code-ui")
    public String customOttRequestPage(HttpServletRequest request, Model model) {
        addCommonModelAttributes(request, model);

        FactorContext factorContext = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        String username = factorContext != null && StringUtils.hasText(factorContext.getUsername())
                ? factorContext.getUsername() : resolveUsername();
        model.addAttribute("username", username);
        model.addAttribute("ottRequestUrl", authUrlProvider.getOttCodeGeneration());
        model.addAttribute("hiddenInputsHtml", buildHiddenInputs(request, false, null));
        model.addAttribute("errorCode", request.getParameter("error"));

        return "custom/mfa-ott-request";
    }

    @GetMapping("/custom/mfa/challenge/ott")
    public String customOttVerifyPage(HttpServletRequest request, Model model) {
        addCommonModelAttributes(request, model);

        FactorContext factorContext = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        int attemptsMade = factorContext != null ? factorContext.getRetryCount() : 0;
        int maxAttempts = authContextProperties.getMfa().getMaxRetryAttempts();
        String username = factorContext != null && StringUtils.hasText(factorContext.getUsername())
                ? factorContext.getUsername() : resolveUsername();

        model.addAttribute("username", username);
        model.addAttribute("ottVerifyUrl", authUrlProvider.getOttLoginProcessing());
        model.addAttribute("ottResendUrl", authUrlProvider.getOttCodeGeneration());
        model.addAttribute("attemptsMade", attemptsMade);
        model.addAttribute("maxAttempts", maxAttempts);
        model.addAttribute("hiddenInputsHtml", buildHiddenInputs(request, false, null));
        model.addAttribute("resendHiddenInputsHtml", buildHiddenInputs(request, true, username));
        model.addAttribute("mfaFailureUrl", authUrlProvider.getMfaFailure());

        return "custom/mfa-ott-verify";
    }

    @GetMapping("/custom/challenge/passkey")
    public String customPasskeyChallengePage(HttpServletRequest request, Model model) {
        addCommonModelAttributes(request, model);

        FactorContext factorContext = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        String username = factorContext != null && StringUtils.hasText(factorContext.getUsername())
                ? factorContext.getUsername() : resolveUsername();
        model.addAttribute("username", username);
        model.addAttribute("mfaFailureUrl", authUrlProvider.getMfaFailure());
        model.addAttribute("passkeyRegistrationUrl", "/webauthn/register");

        return "custom/mfa-passkey";
    }

    private void addCommonModelAttributes(HttpServletRequest request, Model model) {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String mfaSessionId = resolveMfaSessionId(request);

        model.addAttribute("contextPath", request.getContextPath());
        model.addAttribute("csrfToken", csrfToken != null ? csrfToken.getToken() : "");
        model.addAttribute("csrfHeaderName", csrfToken != null ? csrfToken.getHeaderName() : "X-CSRF-TOKEN");
        model.addAttribute("csrfParameterName", csrfToken != null ? csrfToken.getParameterName() : "_csrf");
        model.addAttribute("tokenPersistence", resolveTokenPersistence());
        model.addAttribute("mfaSessionId", mfaSessionId);
        model.addAttribute("mfaSdkRequired", true);
    }

    private String resolveTokenPersistence() {
        String tokenPersistence = authContextProperties.getTokenPersistence();
        return StringUtils.hasText(tokenPersistence) ? tokenPersistence : "memory";
    }

    private String resolveMfaSessionId(HttpServletRequest request) {
        Object requestAttributeSessionId = request.getAttribute("mfaSessionId");
        if (requestAttributeSessionId instanceof String sessionId && StringUtils.hasText(sessionId)) {
            return sessionId;
        }

        String repositorySessionId = mfaSessionRepository.getSessionId(request);
        return StringUtils.hasText(repositorySessionId) ? repositorySessionId : "";
    }

    private String buildHiddenInputs(HttpServletRequest request, boolean includeUsername, String username) {
        Map<String, String> hiddenInputs = new LinkedHashMap<>();
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            hiddenInputs.put(csrfToken.getParameterName(), csrfToken.getToken());
        }

        String mfaSessionId = resolveMfaSessionId(request);
        if (StringUtils.hasText(mfaSessionId)) {
            hiddenInputs.put("mfaSessionId", mfaSessionId);
        }

        if (includeUsername && StringUtils.hasText(username)) {
            hiddenInputs.put("username", username);
        }

        return hiddenInputs.entrySet()
                .stream()
                .map(entry -> "<input type=\"hidden\" name=\"" + escapeHtml(entry.getKey()) +
                        "\" value=\"" + escapeHtml(entry.getValue()) + "\" />")
                .collect(Collectors.joining("\n"));
    }

    private String resolveUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return authentication.getName();
        }
        return "";
    }

    private String escapeHtml(String input) {
        return input == null ? "" : HtmlUtils.htmlEscape(input);
    }
}
