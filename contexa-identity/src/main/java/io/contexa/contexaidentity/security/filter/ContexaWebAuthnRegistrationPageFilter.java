package io.contexa.contexaidentity.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Contexa replacement for Spring Security's DefaultWebAuthnRegistrationPageGeneratingFilter.
 * Supports dynamic URL via setRequestMatcher() and uses unified Contexa MFA CSS styling.
 *
 * Based on Spring Security 6.5 original (Apache 2.0 License).
 */
@Slf4j
public class ContexaWebAuthnRegistrationPageFilter extends OncePerRequestFilter {

    private RequestMatcher matcher = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.GET, "/webauthn/register");

    private final PublicKeyCredentialUserEntityRepository userEntities;
    private final UserCredentialRepository userCredentials;
    private MessageSource messageSource;

    public ContexaWebAuthnRegistrationPageFilter(PublicKeyCredentialUserEntityRepository userEntities,
                                                  UserCredentialRepository userCredentials) {
        Assert.notNull(userEntities, "userEntities cannot be null");
        Assert.notNull(userCredentials, "userCredentials cannot be null");
        this.userEntities = userEntities;
        this.userCredentials = userCredentials;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    private String msg(String code, String defaultMsg) {
        if (messageSource == null) {
            return defaultMsg;
        }
        return messageSource.getMessage(code, null, defaultMsg, LocaleContextHolder.getLocale());
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.matcher = requestMatcher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!this.matcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);

        String html = MfaHtmlTemplates.fromTemplate(HTML_TEMPLATE)
                .withValue("contextPath", request.getContextPath())
                .withRawHtml("csrfHeaders", csrfToken != null ? renderCsrfHeader(csrfToken) : "{}")
                .withRawHtml("passkeys", passkeyRows(request.getRemoteUser(), request.getContextPath(), csrfToken))
                .withValue("i18nTitle", msg("webauthn.title", "Passkey Management"))
                .withValue("i18nDescription", msg("webauthn.description", "Register and manage your passkeys for secure authentication."))
                .withValue("i18nLabel", msg("webauthn.label", "Passkey Label"))
                .withValue("i18nLabelPlaceholder", msg("webauthn.label.placeholder", "e.g. My MacBook, YubiKey"))
                .withValue("i18nRegisterButton", msg("webauthn.register.button", "Register New Passkey"))
                .withValue("i18nTableLabel", msg("webauthn.table.label", "Label"))
                .withValue("i18nTableCreated", msg("webauthn.table.created", "Created"))
                .withValue("i18nTableLastUsed", msg("webauthn.table.lastused", "Last Used"))
                .withValue("i18nTableSignatures", msg("webauthn.table.signatures", "Signatures"))
                .withValue("i18nTableAction", msg("webauthn.table.action", "Action"))
                .withValue("i18nSuccess", msg("webauthn.success", "Passkey registered successfully!"))
                .render();

        response.getWriter().write(html);
    }

    private String passkeyRows(String username, String contextPath, CsrfToken csrfToken) {
        PublicKeyCredentialUserEntity userEntity = this.userEntities.findByUsername(username);
        List<CredentialRecord> credentials = (userEntity != null)
                ? this.userCredentials.findByUserId(userEntity.getId()) : Collections.emptyList();
        if (credentials.isEmpty()) {
            String emptyMsg = msg("webauthn.empty", "No Passkeys registered");
            return "<tr><td colspan=\"5\" style=\"text-align:center; color:#999; padding:20px;\">" + emptyMsg + "</td></tr>";
        }
        return credentials.stream()
                .map(cr -> renderPasskeyRow(cr, contextPath, csrfToken))
                .collect(Collectors.joining("\n"));
    }

    private String renderPasskeyRow(CredentialRecord credential, String contextPath, CsrfToken csrfToken) {
        return MfaHtmlTemplates.fromTemplate(PASSKEY_ROW_TEMPLATE)
                .withValue("label", credential.getLabel())
                .withValue("created", formatInstant(credential.getCreated()))
                .withValue("lastUsed", formatInstant(credential.getLastUsed()))
                .withValue("signatureCount", String.valueOf(credential.getSignatureCount()))
                .withValue("credentialId", credential.getCredentialId().toBase64UrlString())
                .withValue("csrfParameterName", csrfToken != null ? csrfToken.getParameterName() : "_csrf")
                .withValue("csrfToken", csrfToken != null ? csrfToken.getToken() : "")
                .withValue("contextPath", contextPath)
                .withValue("deleteLabel", msg("webauthn.delete", "Delete"))
                .render();
    }

    private static String formatInstant(Instant instant) {
        if (instant == null) {
            return "-";
        }
        return ZonedDateTime.ofInstant(instant, ZoneId.of("UTC"))
                .truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_INSTANT);
    }

    private String renderCsrfHeader(CsrfToken csrfToken) {
        if (csrfToken == null) {
            return "{}";
        }
        return MfaHtmlTemplates.fromTemplate(CSRF_HEADERS)
                .withValue("headerName", csrfToken.getHeaderName())
                .withValue("headerValue", csrfToken.getToken())
                .render();
    }

    private static final String HTML_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <title>{{i18nTitle}}</title>
                <script type="text/javascript" src="{{contextPath}}/login/webauthn.js"></script>
                <script type="text/javascript">
                    const ui = {
                        getRegisterButton: function() { return document.getElementById('register'); },
                        getSuccess: function() { return document.getElementById('success'); },
                        getError: function() { return document.getElementById('error'); },
                        getLabelInput: function() { return document.getElementById('label'); },
                        getDeleteForms: function() { return Array.from(document.getElementsByClassName("delete-form")); },
                    };
                    document.addEventListener("DOMContentLoaded", () => setupRegistration({{csrfHeaders}}, "{{contextPath}}", ui));
                </script>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        padding: 20px;
                    }
                    .container {
                        background: white;
                        border-radius: 12px;
                        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                        padding: 40px;
                        max-width: 680px;
                        width: 100%;
                    }
                    h1 {
                        color: #333;
                        font-size: 24px;
                        margin-bottom: 8px;
                        text-align: center;
                    }
                    .description {
                        color: #666;
                        font-size: 14px;
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .form-group { margin-bottom: 20px; }
                    label {
                        display: block;
                        color: #555;
                        font-size: 14px;
                        font-weight: 500;
                        margin-bottom: 8px;
                    }
                    .form-control {
                        width: 100%;
                        padding: 12px 16px;
                        font-size: 15px;
                        border: 1.5px solid #e0e0e0;
                        border-radius: 8px;
                        transition: all 0.2s;
                    }
                    .form-control:focus {
                        outline: none;
                        border-color: #667eea;
                        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                    }
                    .primary-button {
                        width: 100%;
                        padding: 14px;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        border: none;
                        border-radius: 8px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: transform 0.2s, box-shadow 0.2s;
                    }
                    .primary-button:hover:not(:disabled) {
                        transform: translateY(-2px);
                        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
                    }
                    .primary-button:active:not(:disabled) { transform: translateY(0); }
                    .primary-button:disabled { opacity: 0.6; cursor: not-allowed; }
                    .small-button {
                        padding: 8px 16px;
                        background: #e53935;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        font-size: 13px;
                        font-weight: 500;
                        cursor: pointer;
                        transition: background 0.2s;
                    }
                    .small-button:hover { background: #c62828; }
                    .alert {
                        padding: 12px 16px;
                        border-radius: 8px;
                        font-size: 14px;
                        margin-bottom: 20px;
                        display: none;
                    }
                    .alert-success {
                        background: #e8f5e9;
                        color: #2e7d32;
                        border: 1px solid #a5d6a7;
                    }
                    .alert-danger {
                        background: #fff0f0;
                        color: #d32f2f;
                        border: 1px solid #ffcdd2;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 30px;
                    }
                    th {
                        background: #f5f5f5;
                        color: #555;
                        font-size: 13px;
                        font-weight: 600;
                        text-transform: uppercase;
                        padding: 12px 16px;
                        text-align: left;
                        border-bottom: 2px solid #e0e0e0;
                    }
                    td {
                        padding: 12px 16px;
                        font-size: 14px;
                        color: #333;
                        border-bottom: 1px solid #f0f0f0;
                        vertical-align: middle;
                    }
                    tr:hover { background: #fafafa; }
                    .no-margin { margin: 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>{{i18nTitle}}</h1>
                    <p class="description">{{i18nDescription}}</p>
                    <form method="post" action="#" onclick="return false">
                        <div id="success" class="alert alert-success">{{i18nSuccess}}</div>
                        <div id="error" class="alert alert-danger"></div>
                        <div class="form-group">
                            <label for="label">{{i18nLabel}}</label>
                            <input type="text" id="label" name="label" class="form-control"
                                   placeholder="{{i18nLabelPlaceholder}}" required autofocus>
                        </div>
                        <button id="register" class="primary-button" type="submit">{{i18nRegisterButton}}</button>
                    </form>
                    <table>
                        <thead>
                            <tr>
                                <th>{{i18nTableLabel}}</th>
                                <th>{{i18nTableCreated}}</th>
                                <th>{{i18nTableLastUsed}}</th>
                                <th>{{i18nTableSignatures}}</th>
                                <th>{{i18nTableAction}}</th>
                            </tr>
                        </thead>
                        <tbody>
            {{passkeys}}
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
            """;

    private static final String PASSKEY_ROW_TEMPLATE = """
                            <tr>
                                <td>{{label}}</td>
                                <td>{{created}}</td>
                                <td>{{lastUsed}}</td>
                                <td style="text-align:center;">{{signatureCount}}</td>
                                <td>
                                    <form class="delete-form no-margin" method="post" action="{{contextPath}}/webauthn/register/{{credentialId}}">
                                        <input type="hidden" name="method" value="delete">
                                        <input type="hidden" name="{{csrfParameterName}}" value="{{csrfToken}}">
                                        <button class="small-button" type="submit">{{deleteLabel}}</button>
                                    </form>
                                </td>
                            </tr>
            """;

    private static final String CSRF_HEADERS = """
            {"{{headerName}}" : "{{headerValue}}"}""";
}
