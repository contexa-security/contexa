/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.zerotrust.stepup;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedStepUp;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.Map;

/**
 * The pages of the verification-only step-up of HOST_OWNED (ownership design S-2). They are reached through the
 * application's own Spring Security chain, so the user is the one the application signed in, and the application's
 * CSRF protection applies to the posts. Nothing here writes the application's authentication, session or cookies.
 * <p>
 * Under {@link HostOwnedStepUp#CONSOLE_STEP_UP_PATH} the same pages answer a console session, behind the console's chain
 * and its CSRF protection, and lead back to the block list.
 */
@Slf4j
@Controller
@RequestMapping({HostOwnedStepUp.STEP_UP_PATH, HostOwnedStepUp.CONSOLE_STEP_UP_PATH})
public class HostOwnedStepUpController {

    private static final TypeReference<PublicKeyCredential<AuthenticatorAssertionResponse>> ASSERTION =
            new TypeReference<>() { };
    private static final TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse>> ATTESTATION =
            new TypeReference<>() { };

    private static final String BLOCK_LIST = "/contexa/admin/blacklist";

    private final HostOwnedStepUpService service;
    private final ObjectMapper json = new ObjectMapper().registerModule(new WebauthnJackson2Module());

    public HostOwnedStepUpController(HostOwnedStepUpService service) {
        this.service = service;
    }

    @GetMapping
    public String page(HttpServletRequest request, Model model) {
        HostOwnedStepUpService.Situation situation = service.situation(request, currentUser());
        model.addAttribute("situation", situation);
        model.addAttribute("purpose", situation != null && situation.purpose() != null
                ? situation.purpose().name() : null);
        model.addAttribute("returnUrl", returnUrl(request));
        model.addAttribute("stepUpBase", stepUpBase(request));
        return "contexa/zero-trust/step-up";
    }

    @PostMapping(value = "/code", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendCode(HttpServletRequest request) {
        Authentication user = currentUser();
        if (user == null) {
            return unauthorized();
        }
        HostOwnedStepUpService.CodeSending sending = service.sendCode(request, user);
        return ResponseEntity.ok(Map.of("sent", sending == HostOwnedStepUpService.CodeSending.SENT,
                "wait", sending == HostOwnedStepUpService.CodeSending.TOO_SOON));
    }

    @PostMapping(value = "/code/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifyCode(HttpServletRequest request,
                                                          @RequestParam("code") String code) {
        Authentication user = currentUser();
        if (user == null) {
            return unauthorized();
        }
        if (!service.verifyCode(request, user, code)) {
            return verified(request, false);
        }
        // Q-1: the moment the user proved who they are is the moment to offer the passkey that spares the next code.
        HostOwnedStepUpService.Situation situation = service.situation(request, user);
        return situation != null && situation.passkeyRegistrable()
                ? ResponseEntity.ok(Map.of("verified", true, "redirectUrl", stepUpBase(request)))
                : verified(request, true);
    }

    @PostMapping(value = "/passkey/options", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<String> passkeyOptions(HttpServletRequest request) throws IOException {
        Authentication user = currentUser();
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        PublicKeyCredentialRequestOptions options = service.passkeyOptions(request, user);
        return options == null ? ResponseEntity.badRequest().build()
                : ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(options));
    }

    @PostMapping(value = "/passkey/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifyPasskey(HttpServletRequest request, @RequestBody String body) {
        Authentication user = currentUser();
        if (user == null) {
            return unauthorized();
        }
        try {
            return verified(request, service.verifyPasskey(request, user, json.readValue(body, ASSERTION)));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of("verified", false));
        }
    }

    @PostMapping(value = "/passkey/register/options", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<String> registrationOptions(HttpServletRequest request) throws IOException {
        Authentication user = currentUser();
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        PublicKeyCredentialCreationOptions options = service.registrationOptions(request, user);
        return options == null ? ResponseEntity.badRequest().build()
                : ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(options));
    }

    @PostMapping(value = "/passkey/register", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> registerPasskey(HttpServletRequest request, @RequestBody String body) {
        Authentication user = currentUser();
        if (user == null) {
            return unauthorized();
        }
        try {
            JsonNode node = json.readTree(body);
            PublicKeyCredential<AuthenticatorAttestationResponse> credential =
                    json.readValue(json.treeAsTokens(node.path("credential")), ATTESTATION);
            String label = node.path("label").asText("passkey");
            return ResponseEntity.ok(Map.of("registered", service.registerPasskey(request, user, credential, label)));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of("registered", false));
        }
    }

    private static Authentication currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken) ? authentication : null;
    }

    private static ResponseEntity<Map<String, Object>> verified(HttpServletRequest request, boolean verified) {
        return verified
                ? ResponseEntity.ok(Map.of("verified", true, "redirectUrl", returnUrl(request)))
                : ResponseEntity.status(400).body(Map.of("verified", false));
    }

    private static String stepUpBase(HttpServletRequest request) {
        return request.getContextPath()
                + (ConsoleSession.of(request) ? HostOwnedStepUp.CONSOLE_STEP_UP_PATH : HostOwnedStepUp.STEP_UP_PATH);
    }

    private static String returnUrl(HttpServletRequest request) {
        return request.getContextPath() + (ConsoleSession.of(request) ? BLOCK_LIST : "/");
    }

    private static ResponseEntity<Map<String, Object>> unauthorized() {
        return ResponseEntity.status(401).body(Map.of("error", "AUTHENTICATION_REQUIRED"));
    }
}
