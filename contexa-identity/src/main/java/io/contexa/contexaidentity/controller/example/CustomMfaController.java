package io.contexa.contexaidentity.controller.example;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.enums.AuthType;
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


@Slf4j
@Controller
@RequestMapping("/custom/mfa")
@RequiredArgsConstructor
@ConditionalOnBean(MfaStateMachineIntegrator.class)
public class CustomMfaController {

    private final MfaStateMachineIntegrator stateMachineIntegrator;

    
    @GetMapping("/select")
    public String selectFactorPage(Model model, HttpServletRequest request) {
        
        String mfaSessionId = (String) request.getAttribute("mfaSessionId");
        String username = (String) request.getAttribute("username");

        
        List<AuthType> factors = extractAvailableFactors(request);

        
        
        
        
        

        model.addAttribute("mfaSessionId", mfaSessionId);
        model.addAttribute("username", username);
        model.addAttribute("factors", factors);

        log.debug("Custom MFA select factor page for user: {}", username);

        
        return "custom/react-mfa-select-factor";
    }

    
    @GetMapping("/ott-request")
    public String ottRequestPage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("currentState", ctx.getCurrentState().name());

        log.debug("Custom OTT request page for session: {}", ctx.getMfaSessionId());

        
        return "custom/vue-mfa-ott-request";
    }

    
    @GetMapping("/ott-verify")
    public String ottVerifyPage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("currentState", ctx.getCurrentState().name());

        log.debug("Custom OTT verify page for session: {}", ctx.getMfaSessionId());

        
        return "custom/angular-mfa-ott-verify";
    }

    
    @GetMapping("/passkey")
    public String passkeyChallengePage(Model model, HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("currentState", ctx.getCurrentState().name());

        log.debug("Custom Passkey challenge page for session: {}", ctx.getMfaSessionId());

        
        return "custom/vanilla-mfa-passkey";
    }

    
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

    
    @GetMapping("/failure")
    public String failurePage(Model model, HttpServletRequest request) {
        String errorMessage = request.getParameter("error");
        model.addAttribute("errorMessage", errorMessage != null ? errorMessage : "인증에 실패했습니다.");

        log.debug("Custom MFA failure page with error: {}", errorMessage);

        return "custom/mfa-failure";
    }

    
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
