package io.contexa.contexaidentity.security.service;

import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaPageConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;
import jakarta.annotation.PostConstruct;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
public class AuthUrlProvider {

    private final AuthContextProperties properties;
    private MfaPageConfig mfaPageConfig = new MfaPageConfig();

    private final Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new HashMap<>();

    private PrimaryAuthenticationOptions primaryAuthOptions;
    private String urlPrefix;

    public AuthUrlProvider(AuthContextProperties properties) {
        this.properties = properties;
    }

    public void setUrlPrefix(String urlPrefix) {
        this.urlPrefix = urlPrefix;
    }

    public String getUrlPrefix() {
        return this.urlPrefix;
    }

    private String applyPrefix(String url) {
        if (urlPrefix != null && url != null && !url.startsWith(urlPrefix)) {
            return urlPrefix + url;
        }
        return url;
    }

    public void setPrimaryAuthenticationOptions(@Nullable PrimaryAuthenticationOptions primaryAuthOptions) {
        if (primaryAuthOptions != null) {

            this.primaryAuthOptions = primaryAuthOptions;

        }
    }

    public void setMfaPageConfig(@Nullable MfaPageConfig mfaPageConfig) {
        if (mfaPageConfig != null) {
            this.mfaPageConfig = mfaPageConfig;
        }
    }

    public void updateFactorOptions(@Nullable Map<AuthType, AuthenticationProcessingOptions> options) {
        if (options != null && !options.isEmpty()) {
            this.factorOptionsMap.clear();
            this.factorOptionsMap.putAll(options);
        }
    }

    public String getPrimaryFormLoginProcessing() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getLoginProcessingUrl())) {
            if (primaryAuthOptions.isFormLogin()) {
                return applyPrefix(primaryAuthOptions.getLoginProcessingUrl());
            }
        }
        return applyPrefix(properties.getUrls().getPrimary().getFormLoginProcessing());
    }

    public String getPrimaryRestLoginProcessing() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getLoginProcessingUrl())) {
            if (primaryAuthOptions.isRestLogin()) {
                return applyPrefix(primaryAuthOptions.getLoginProcessingUrl());
            }
        }
        return applyPrefix(properties.getUrls().getPrimary().getRestLoginProcessing());
    }

    public String getPrimaryLoginPage() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getLoginPage())) {
            return applyPrefix(primaryAuthOptions.getLoginPage());
        }
        return applyPrefix(properties.getUrls().getPrimary().getFormLoginPage());
    }

    public String getDefaultPrimaryLoginPage() {
        return applyPrefix(properties.getUrls().getPrimary().getFormLoginPage());
    }

    public String getPrimaryLoginFailure() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getFailureUrl())) {
            return applyPrefix(primaryAuthOptions.getFailureUrl());
        }
        return applyPrefix(properties.getUrls().getPrimary().getLoginFailure());
    }

    public String getPrimaryLoginSuccess() {
        return applyPrefix(properties.getUrls().getPrimary().getLoginSuccess());
    }

    public String getLogoutPage() {
        return applyPrefix(properties.getUrls().getPrimary().getLogoutPage());
    }

    public String getSingleFormLoginProcessing() {
        return properties.getUrls().getSingle().getFormLoginProcessing();
    }

    public String getSingleFormLoginPage() {
        return properties.getUrls().getSingle().getFormLoginPage();
    }

    public String getSingleRestLoginProcessing() {
        return properties.getUrls().getSingle().getRestLoginProcessing();
    }

    public String getSingleLoginFailure() {
        return properties.getUrls().getSingle().getLoginFailure();
    }

    public String getSingleLoginSuccess() {
        return properties.getUrls().getSingle().getLoginSuccess();
    }

    public String getSingleOttRequestEmail() {
        return properties.getUrls().getSingle().getOtt().getRequestEmail();
    }

    public String getSingleOttCodeGeneration() {
        return properties.getUrls().getSingle().getOtt().getCodeGeneration();
    }

    public String getSingleOttCodeSent() {
        return properties.getUrls().getSingle().getOtt().getCodeSent();
    }

    public String getSingleOttChallenge() {
        return properties.getUrls().getSingle().getOtt().getChallenge();
    }

    public String getSingleOttLoginProcessing() {
        return properties.getUrls().getSingle().getOtt().getLoginProcessing();
    }

    public String getSingleOttSent() {
        return properties.getUrls().getFactors().getOtt().getSingleOttSent();
    }

    public String getSingleOttLoginFailure() {
        return properties.getUrls().getSingle().getOtt().getLoginFailure();
    }

    public String getSinglePasskeyLoginPage() {
        return properties.getUrls().getSingle().getPasskey().getLoginPage();
    }

    public String getSinglePasskeyLoginProcessing() {
        return properties.getUrls().getSingle().getPasskey().getLoginProcessing();
    }

    public String getSinglePasskeyLoginFailure() {
        return properties.getUrls().getSingle().getPasskey().getLoginFailure();
    }

    public String getSinglePasskeyAssertionOptions() {
        return properties.getUrls().getSingle().getPasskey().getAssertionOptions();
    }

    public String getSinglePasskeyRegistrationOptions() {
        return properties.getUrls().getSingle().getPasskey().getRegistrationOptions();
    }

    public String getSinglePasskeyRegistrationProcessing() {
        return properties.getUrls().getSingle().getPasskey().getRegistrationProcessing();
    }

    public String getMfaSelectFactor() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomSelectFactorPage()) {
            return applyPrefix(mfaPageConfig.getSelectFactorPageUrl());
        }
        return applyPrefix(properties.getUrls().getMfa().getSelectFactor());
    }

    public String getMfaSuccess() {
        return applyPrefix(properties.getUrls().getMfa().getSuccess());
    }

    public String getMfaFailure() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomFailurePage()) {
            return applyPrefix(mfaPageConfig.getFailurePageUrl());
        }
        return applyPrefix(properties.getUrls().getMfa().getFailure());
    }

    public String getMfaCancel() {
        return applyPrefix(properties.getUrls().getMfa().getCancel());
    }

    public String getMfaStatus() {
        return applyPrefix(properties.getUrls().getMfa().getStatus());
    }

    public String getMfaRequestOttCode() {
        return applyPrefix(properties.getUrls().getMfa().getRequestOttCode());
    }

    public String getMfaConfig() {
        return applyPrefix(properties.getUrls().getMfa().getConfig());
    }

    public String getOttRequestCodeUi() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttRequestPage()) {
            return applyPrefix(mfaPageConfig.getOttRequestPageUrl());
        }
        return applyPrefix(properties.getUrls().getFactors().getOtt().getRequestCodeUi());
    }

    public String getOttCodeGeneration() {
        AuthenticationProcessingOptions ottOpts = factorOptionsMap.get(AuthType.MFA_OTT);
        if (ottOpts instanceof OttOptions ottOptions) {
            String customUrl = ottOptions.getTokenGeneratingUrl();
            if (StringUtils.hasText(customUrl)) {
                return applyPrefix(customUrl);
            }
        }

        return applyPrefix(properties.getUrls().getFactors().getOtt().getCodeGeneration());
    }

    public String getOttChallengeUi() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttVerifyPage()) {
            return applyPrefix(mfaPageConfig.getOttVerifyPageUrl());
        }

        AuthenticationProcessingOptions ottOpts = factorOptionsMap.get(AuthType.MFA_OTT);
        if (ottOpts instanceof OttOptions ottOptions) {
            String customUrl = ottOptions.getDefaultSubmitPageUrl();
            if (StringUtils.hasText(customUrl)) {
                return applyPrefix(customUrl);
            }
        }

        return applyPrefix(properties.getUrls().getFactors().getOtt().getChallengeUi());
    }

    public String getOttLoginProcessing() {
        AuthenticationProcessingOptions ottOpts = factorOptionsMap.get(AuthType.MFA_OTT);
        if (ottOpts instanceof OttOptions ottOptions) {
            String customUrl = ottOptions.getLoginProcessingUrl();
            if (StringUtils.hasText(customUrl)) {
                return applyPrefix(customUrl);
            }
        }

        return applyPrefix(properties.getUrls().getFactors().getOtt().getLoginProcessing());
    }

    public String getMfaOttCodeGeneration() {
        return getOttCodeGeneration();
    }

    public String getMfaOttChallengeUi() {
        return getOttChallengeUi();
    }

    public String getMfaOttLoginProcessing() {
        return getOttLoginProcessing();
    }

    public String getOttCodeSent() {
        return applyPrefix(properties.getUrls().getFactors().getOtt().getCodeSent());
    }

    public String getOttDefaultFailure() {
        return applyPrefix(properties.getUrls().getFactors().getOtt().getDefaultFailure());
    }

    public String getPasskeyLoginProcessing() {
        AuthenticationProcessingOptions passkeyOpts = factorOptionsMap.get(AuthType.MFA_PASSKEY);
        if (passkeyOpts instanceof PasskeyOptions passkeyOptions) {
            String customUrl = passkeyOptions.getLoginProcessingUrl();
            if (StringUtils.hasText(customUrl)) {
                return applyPrefix(customUrl);
            }
        }

        return applyPrefix(properties.getUrls().getFactors().getPasskey().getLoginProcessing());
    }

    public String getPasskeyAssertionOptions() {
        AuthenticationProcessingOptions passkeyOpts = factorOptionsMap.get(AuthType.MFA_PASSKEY);
        if (passkeyOpts instanceof PasskeyOptions passkeyOptions) {
            String customUrl = passkeyOptions.getAssertionOptionsEndpoint();
            if (StringUtils.hasText(customUrl)) {
                return applyPrefix(customUrl);
            }
        }

        return applyPrefix(properties.getUrls().getFactors().getPasskey().getAssertionOptions());
    }

    public String getMfaPasskeyLoginProcessing() {
        return getPasskeyLoginProcessing();
    }

    public String getMfaPasskeyAssertionOptions() {
        return getPasskeyAssertionOptions();
    }

    public String getPasskeyChallengeUi() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomPasskeyPage()) {
            return applyPrefix(mfaPageConfig.getPasskeyChallengePageUrl());
        }
        return applyPrefix(properties.getUrls().getFactors().getPasskey().getChallengeUi());
    }

    public String getPasskeyRegistrationProcessing() {
        return applyPrefix(properties.getUrls().getFactors().getPasskey().getRegistrationProcessing());
    }

    public String getPasskeyRegistrationOptions() {
        return applyPrefix(properties.getUrls().getFactors().getPasskey().getRegistrationOptions());
    }

    public String getRecoveryCodeLoginProcessing() {
        return applyPrefix(properties.getUrls().getFactors().getRecoveryCodeLoginProcessing());
    }

    public String getRecoveryCodeChallengeUi() {
        return applyPrefix(properties.getUrls().getFactors().getRecoveryCodeChallengeUi());
    }

    public List<String> getAllFactorProcessingUrls() {
        return List.of(
                getOttLoginProcessing(),
                getPasskeyLoginProcessing(),
                getRecoveryCodeLoginProcessing()
        );
    }

    public Set<String> getMfaPageUrls() {
        return Set.of(
                getMfaSelectFactor(),
                getMfaFailure(),
                getMfaSuccess(),
                getOttRequestCodeUi(),
                getOttChallengeUi(),
                getPasskeyChallengeUi(),
                getRecoveryCodeChallengeUi()
        );
    }

    public List<String> getAllMfaRequestUrls() {
        return List.of(
                getMfaSelectFactor(),
                getOttCodeGeneration(),
                getOttLoginProcessing(),
                getPasskeyLoginProcessing()
        );
    }

    public Map<String, Object> getAllUiPageUrls() {
        Map<String, Object> urls = new LinkedHashMap<>();

        urls.put("primary", Map.of(
                "formLoginPage", getPrimaryLoginPage(),
                "formLoginProcessing", getPrimaryFormLoginProcessing(),
                "restLoginProcessing", getPrimaryRestLoginProcessing(),
                "loginFailure", getPrimaryLoginFailure(),
                "loginSuccess", getPrimaryLoginSuccess()
        ));

        urls.put("mfa", Map.of(
                "selectFactor", getMfaSelectFactor(),
                "success", getMfaSuccess(),
                "failure", getMfaFailure(),
                "cancel", getMfaCancel()
        ));

        Map<String, String> ottUrls = new LinkedHashMap<>();
        ottUrls.put("requestCodeUi", getOttRequestCodeUi());
        ottUrls.put("challengeUi", getOttChallengeUi());
        ottUrls.put("loginProcessing", getOttLoginProcessing());
        ottUrls.put("codeSent", getOttCodeSent());
        ottUrls.put("codeGeneration", getOttCodeGeneration());
        ottUrls.put("defaultFailure", getOttDefaultFailure());
        ottUrls.put("singleOttRequestEmail", getSingleOttRequestEmail());
        ottUrls.put("singleOttCodeGeneration", getSingleOttCodeGeneration());
        ottUrls.put("singleOttChallenge", getSingleOttChallenge());
        ottUrls.put("singleOttSent", getSingleOttSent());
        urls.put("ott", ottUrls);

        Map<String, String> passkeyUrls = new LinkedHashMap<>();
        passkeyUrls.put("challengeUi", getPasskeyChallengeUi());
        passkeyUrls.put("loginProcessing", getPasskeyLoginProcessing());
        passkeyUrls.put("registrationProcessing", getPasskeyRegistrationProcessing());
        urls.put("passkey", passkeyUrls);

        urls.put("recoveryCode", Map.of(
                "challengeUi", getRecoveryCodeChallengeUi(),
                "loginProcessing", getRecoveryCodeLoginProcessing()
        ));

        urls.put("webauthn", Map.of(
                "assertionOptions", getPasskeyAssertionOptions(),
                "assertionVerify", getPasskeyLoginProcessing()
        ));

        urls.put("api", Map.of(
                "selectFactor", getMfaSelectFactor(),
                "cancel", getMfaCancel(),
                "status", getMfaStatus(),
                "requestOttCode", getMfaRequestOttCode(),
                "config", getMfaConfig()
        ));

        return urls;
    }

    @PostConstruct
    public void validateConfiguration() {
        List<String> errors = new ArrayList<>();
        Map<String, List<String>> urlToContexts = new LinkedHashMap<>();

        addUrlWithContext(urlToContexts, getPrimaryFormLoginProcessing(), "Primary.formLoginProcessing");
        addUrlWithContext(urlToContexts, getPrimaryRestLoginProcessing(), "Primary.restLoginProcessing");
        addUrlWithContext(urlToContexts, getPrimaryLoginPage(), "Primary.formLoginPage");
        addUrlWithContext(urlToContexts, getPrimaryLoginFailure(), "Primary.loginFailure");
        addUrlWithContext(urlToContexts, getPrimaryLoginSuccess(), "Primary.loginSuccess");
        addUrlWithContext(urlToContexts, getLogoutPage(), "Primary.logoutPage");

        addUrlWithContext(urlToContexts, getMfaSelectFactor(), "Mfa.selectFactor");
        addUrlWithContext(urlToContexts, getMfaSuccess(), "Mfa.success");
        addUrlWithContext(urlToContexts, getMfaFailure(), "Mfa.failure");
        addUrlWithContext(urlToContexts, getMfaCancel(), "Mfa.cancel");

        addUrlWithContext(urlToContexts, getOttRequestCodeUi(), "Ott.requestCodeUi");
        addUrlWithContext(urlToContexts, getOttCodeGeneration(), "Ott.codeGeneration");
        addUrlWithContext(urlToContexts, getOttCodeSent(), "Ott.codeSent");
        addUrlWithContext(urlToContexts, getOttChallengeUi(), "Ott.challengeUi");
        addUrlWithContext(urlToContexts, getOttLoginProcessing(), "Ott.loginProcessing");
        addUrlWithContext(urlToContexts, getOttDefaultFailure(), "Ott.defaultFailure");
        addUrlWithContext(urlToContexts, getSingleOttRequestEmail(), "Ott.singleOttRequestEmail");
        addUrlWithContext(urlToContexts, getSingleOttCodeGeneration(), "Ott.singleOttCodeGeneration");
        addUrlWithContext(urlToContexts, getSingleOttChallenge(), "Ott.singleOttChallenge");
        addUrlWithContext(urlToContexts, getSingleOttSent(), "Ott.singleOttSent");

        addUrlWithContext(urlToContexts, getPasskeyLoginProcessing(), "Passkey.loginProcessing");
        addUrlWithContext(urlToContexts, getPasskeyChallengeUi(), "Passkey.challengeUi");
        addUrlWithContext(urlToContexts, getPasskeyRegistrationProcessing(), "Passkey.registrationProcessing");
        addUrlWithContext(urlToContexts, getPasskeyRegistrationOptions(), "Passkey.registrationOptions");

        addUrlWithContext(urlToContexts, getRecoveryCodeLoginProcessing(), "RecoveryCode.loginProcessing");
        addUrlWithContext(urlToContexts, getRecoveryCodeChallengeUi(), "RecoveryCode.challengeUi");

        addUrlWithContext(urlToContexts, getMfaStatus(), "Mfa.status");
        addUrlWithContext(urlToContexts, getMfaRequestOttCode(), "Mfa.requestOttCode");
        addUrlWithContext(urlToContexts, getMfaConfig(), "Mfa.config");
        addUrlWithContext(urlToContexts, getPasskeyAssertionOptions(), "Passkey.assertionOptions");

        Set<String> allowedDuplicates = Set.of(
                "/login",
                "/mfa/login",
                "/home",
                "/loginForm"
        );

        List<String> problematicDuplicates = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : urlToContexts.entrySet()) {
            String url = entry.getKey();
            List<String> contexts = entry.getValue();

            if (url == null || url.trim().isEmpty()) {
                errors.add("Empty URL found");
                continue;
            }

            if (contexts.size() > 1) {

                if (!allowedDuplicates.contains(url)) {
                    problematicDuplicates.add(url + " (used by: " + String.join(", ", contexts) + ")");
                } else {
                }
            }
        }

//        if (!problematicDuplicates.isEmpty()) {
//            errors.add("Unintended duplicate URLs found: " + String.join("; ", problematicDuplicates));
//        }

        for (String url : urlToContexts.keySet()) {
            if (!url.startsWith("/")) {
                errors.add("URL must start with '/': " + url);
            }

            if (url.contains(" ")) {
                errors.add("URL contains whitespace: " + url);
            }
        }

        if (!errors.isEmpty()) {
            String errorMessage = " URL configuration validation failed:\n" + String.join("\n", errors);
            log.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        }

    }

    private void addUrlWithContext(Map<String, List<String>> map, String url, String context) {
        if (url == null) return;
        map.computeIfAbsent(url, k -> new ArrayList<>()).add(context);
    }
}
