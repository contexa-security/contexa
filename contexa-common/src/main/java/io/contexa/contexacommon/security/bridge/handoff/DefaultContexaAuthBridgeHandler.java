package io.contexa.contexacommon.security.bridge.handoff;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class DefaultContexaAuthBridgeHandler implements ContexaAuthBridgeHandler {

    private final BridgeProperties properties;
    private final RequestContextCollector requestContextCollector;
    private final BridgeCoverageEvaluator bridgeCoverageEvaluator;
    private final BridgeRuntimeSupport bridgeRuntimeSupport;
    @Nullable
    private final SecurityContextRepository securityContextRepository;

    public DefaultContexaAuthBridgeHandler(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            BridgeCoverageEvaluator bridgeCoverageEvaluator,
            BridgeRuntimeSupport bridgeRuntimeSupport,
            @Nullable SecurityContextRepository securityContextRepository) {
        this.properties = properties != null ? properties : new BridgeProperties();
        this.requestContextCollector = requestContextCollector;
        this.bridgeCoverageEvaluator = bridgeCoverageEvaluator;
        this.bridgeRuntimeSupport = bridgeRuntimeSupport;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public ContexaAuthHandoffResult handoff(ContexaAuthHandoff handoff) {
        return handoff(null, null, handoff);
    }

    @Override
    public ContexaAuthHandoffResult handoff(
            @Nullable HttpServletRequest request,
            @Nullable HttpServletResponse response,
            ContexaAuthHandoff handoff) {
        HandoffWebContext webContext = resolveWebContext(request, response);
        RequestContextSnapshot requestContext = webContext.request() != null
                ? requestContextCollector.collect(webContext.request())
                : createFallbackRequestContext();
        AuthenticationStamp authenticationStamp = buildAuthenticationStamp(handoff, requestContext);
        AuthorizationStamp authorizationStamp = bridgeRuntimeSupport
                .deriveAuthorizationStamp(authenticationStamp, requestContext.requestUri(), requestContext.method())
                .orElse(null);
        BridgeUserMirrorSyncResult userMirrorSyncResult = bridgeRuntimeSupport.synchronizeUser(authenticationStamp, authorizationStamp, requestContext);
        BridgeResolutionResult resolutionResult = new BridgeResolutionResult(
                requestContext,
                authenticationStamp,
                authorizationStamp,
                null,
                bridgeCoverageEvaluator.evaluate(authenticationStamp, authorizationStamp, null)
        );

        if (webContext.request() != null) {
            bridgeRuntimeSupport.writeResolutionAttributes(webContext.request(), resolutionResult, userMirrorSyncResult);
        }

        bridgeRuntimeSupport.populateSecurityContext(authenticationStamp, resolutionResult, userMirrorSyncResult, true);
        bridgeRuntimeSupport.persistSecurityContext(securityContextRepository, webContext.request(), webContext.response());
        return new ContexaAuthHandoffResult(resolutionResult, userMirrorSyncResult);
    }

    private AuthenticationStamp buildAuthenticationStamp(ContexaAuthHandoff handoff, RequestContextSnapshot requestContext) {
        Object rawPrincipal = handoff.principal();
        Object principal = unwrapPrincipal(rawPrincipal);
        BridgeProperties.RequestAttributes requestAttributes = properties.getAuthentication().getRequestAttributes();

        String principalId = resolvePrincipalId(principal, handoff);
        if (principalId == null || principalId.isBlank()) {
            throw new IllegalArgumentException("Unable to resolve principalId from handoff principal.");
        }

        String displayName = resolveDisplayName(principal, handoff, principalId);
        String principalType = resolvePrincipalType(rawPrincipal, principal, handoff);
        List<String> authorities = resolveAuthorities(rawPrincipal, principal, handoff, requestAttributes);
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(principal, requestAttributes.getAttributeKeys()));
        attributes.putAll(handoff.attributes());
        attributes.putIfAbsent("bridgeAuthenticationSource", "EXPLICIT_HANDOFF");
        attributes.putIfAbsent("bridgeHandoffMode", "API");
        putIfAbsent(attributes, "authenticationType", handoff.authenticationType(), extractAuthenticationType(rawPrincipal, principal, requestAttributes));
        putIfAbsent(attributes, "authenticationAssurance", handoff.authenticationAssurance(), extractAuthenticationAssurance(principal, requestAttributes));
        putIfAbsent(attributes, "mfaCompleted", handoff.mfaVerified(), BridgeObjectExtractor.extractBoolean(principal, requestAttributes.getMfaKeys()));
        putIfAbsent(attributes, "authenticationTime", extractInstant(attributes.get("authenticationTime")), BridgeObjectExtractor.extractInstant(principal, requestAttributes.getAuthTimeKeys()));
        putIfAbsent(attributes, "sessionId", requestContext.sessionId(), null);

        String authenticationType = firstText(
                handoff.authenticationType(),
                text(attributes.get("authenticationType")),
                extractAuthenticationType(rawPrincipal, principal, requestAttributes),
                "HANDOFF"
        );
        String authenticationAssurance = firstText(
                handoff.authenticationAssurance(),
                text(attributes.get("authenticationAssurance")),
                extractAuthenticationAssurance(principal, requestAttributes)
        );
        Boolean mfaVerified = firstBoolean(
                handoff.mfaVerified(),
                resolveBoolean(attributes.get("mfaVerified")),
                resolveBoolean(attributes.get("mfaCompleted")),
                BridgeObjectExtractor.extractBoolean(principal, requestAttributes.getMfaKeys())
        );
        Instant authenticationTime = firstInstant(
                extractInstant(attributes.get("authenticationTime")),
                BridgeObjectExtractor.extractInstant(principal, requestAttributes.getAuthTimeKeys())
        );
        attributes.put("authenticationAssuranceEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationAssurance));
        attributes.put("mfaCompletedEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(mfaVerified));
        attributes.put("authenticationTimeEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationTime));

        return new AuthenticationStamp(
                principalId,
                displayName,
                principalType,
                true,
                authenticationType,
                "EXPLICIT_HANDOFF",
                authenticationAssurance,
                mfaVerified,
                authenticationTime,
                requestContext.sessionId(),
                authorities,
                attributes
        );
    }

    private HandoffWebContext resolveWebContext(
            @Nullable HttpServletRequest request,
            @Nullable HttpServletResponse response) {
        if (request != null || response != null) {
            return new HandoffWebContext(request, response);
        }
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes servletRequestAttributes) {
            return new HandoffWebContext(servletRequestAttributes.getRequest(), servletRequestAttributes.getResponse());
        }
        return new HandoffWebContext(null, null);
    }

    private RequestContextSnapshot createFallbackRequestContext() {
        return new RequestContextSnapshot(
                "handoff://local",
                "HANDOFF",
                null,
                "unknown",
                null,
                UUID.randomUUID().toString(),
                null,
                null,
                false,
                Instant.now()
        );
    }

    private Object unwrapPrincipal(Object principal) {
        if (principal instanceof Authentication authentication) {
            return authentication.getPrincipal();
        }
        return principal;
    }

    private String resolvePrincipalId(Object principal, ContexaAuthHandoff handoff) {
        BridgeProperties.RequestAttributes requestAttributes = properties.getAuthentication().getRequestAttributes();
        String explicitPrincipalId = firstText(
                text(handoff.attributes().get("principalId")),
                text(handoff.attributes().get("externalSubjectId")),
                text(handoff.attributes().get("subjectId"))
        );
        if (explicitPrincipalId != null) {
            return explicitPrincipalId;
        }
        if (principal instanceof String textPrincipal && !textPrincipal.isBlank()) {
            return textPrincipal;
        }
        return BridgeObjectExtractor.extractString(principal, requestAttributes.getPrincipalIdKeys());
    }

    private String resolveDisplayName(Object principal, ContexaAuthHandoff handoff, String fallback) {
        String explicitDisplayName = firstText(
                text(handoff.attributes().get("displayName")),
                text(handoff.attributes().get("name")),
                text(handoff.attributes().get("fullName"))
        );
        if (explicitDisplayName != null) {
            return explicitDisplayName;
        }
        String extracted = BridgeObjectExtractor.extractString(principal, properties.getAuthentication().getRequestAttributes().getDisplayNameKeys());
        return extracted != null ? extracted : fallback;
    }

    private String resolvePrincipalType(Object rawPrincipal, Object principal, ContexaAuthHandoff handoff) {
        String explicit = firstText(
                text(handoff.attributes().get("principalType")),
                text(handoff.attributes().get("userType"))
        );
        if (explicit != null) {
            return explicit;
        }
        if (rawPrincipal instanceof Authentication authentication) {
            return authentication.getClass().getSimpleName();
        }
        return principal != null ? principal.getClass().getSimpleName() : null;
    }

    private List<String> resolveAuthorities(
            Object rawPrincipal,
            Object principal,
            ContexaAuthHandoff handoff,
            BridgeProperties.RequestAttributes requestAttributes) {
        LinkedHashSet<String> authorities = new LinkedHashSet<>();
        addAuthorities(authorities, handoff.authorities());
        if (authorities.isEmpty() && rawPrincipal instanceof Authentication authentication) {
            addAuthorities(authorities, authentication.getAuthorities());
        }
        if (authorities.isEmpty()) {
            authorities.addAll(BridgeObjectExtractor.extractStringSet(principal, requestAttributes.getAuthoritiesKeys()));
        }
        return List.copyOf(authorities);
    }

    private void addAuthorities(LinkedHashSet<String> target, @Nullable Collection<?> authorities) {
        if (authorities == null) {
            return;
        }
        for (Object authority : authorities) {
            if (authority == null) {
                continue;
            }
            String value;
            if (authority instanceof GrantedAuthority grantedAuthority) {
                value = grantedAuthority.getAuthority();
            } else {
                value = authority.toString();
            }
            if (value != null && !value.isBlank()) {
                target.add(value.trim());
            }
        }
    }

    private String extractAuthenticationType(Object rawPrincipal, Object principal, BridgeProperties.RequestAttributes requestAttributes) {
        if (rawPrincipal instanceof Authentication authentication) {
            return authentication.getClass().getSimpleName();
        }
        return BridgeObjectExtractor.extractString(principal, requestAttributes.getAuthenticationTypeKeys());
    }

    private String extractAuthenticationAssurance(Object principal, BridgeProperties.RequestAttributes requestAttributes) {
        return BridgeObjectExtractor.extractString(principal, requestAttributes.getAuthenticationAssuranceKeys());
    }

    @Nullable
    private String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    @Nullable
    private String firstText(@Nullable String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    @Nullable
    private Boolean resolveBoolean(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        String text = value.toString().trim();
        if (text.isBlank()) {
            return null;
        }
        return Boolean.parseBoolean(text);
    }

    @Nullable
    private Boolean firstBoolean(@Nullable Boolean... values) {
        if (values == null) {
            return null;
        }
        for (Boolean value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Nullable
    private Instant extractInstant(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochMilli(number.longValue());
        }
        String text = value.toString().trim();
        if (text.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (Exception ignored) {
            return null;
        }
    }

    @Nullable
    private Instant firstInstant(@Nullable Instant... values) {
        if (values == null) {
            return null;
        }
        for (Instant value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private void putIfAbsent(Map<String, Object> attributes, String key, @Nullable Object preferred, @Nullable Object fallback) {
        if (attributes.containsKey(key) && attributes.get(key) != null) {
            return;
        }
        if (preferred != null) {
            attributes.put(key, preferred);
            return;
        }
        if (fallback != null) {
            attributes.put(key, fallback);
        }
    }

    private record HandoffWebContext(
            @Nullable HttpServletRequest request,
            @Nullable HttpServletResponse response
    ) {
    }
}
