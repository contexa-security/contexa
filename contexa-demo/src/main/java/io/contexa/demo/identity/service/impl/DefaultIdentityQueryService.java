package io.contexa.demo.identity.service.impl;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.identity.dto.IdentityView;
import io.contexa.demo.identity.service.AuthenticationView;
import io.contexa.demo.identity.service.IdentityQueryService;
import io.contexa.demo.security.policy.LabSecurityPolicy;
import io.contexa.demo.shared.document.DocumentCodec;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DefaultIdentityQueryService implements IdentityQueryService {

    private final LabProperties lab;
    private final EntryProperties entry;
    private final AuthenticationView authenticationView;
    private final LabSecurityPolicy policy;
    private final DocumentCodec documents;

    public DefaultIdentityQueryService(LabProperties lab, EntryProperties entry, AuthenticationView authenticationView,
            LabSecurityPolicy policy, DocumentCodec documents) {
        this.lab = lab;
        this.entry = entry;
        this.authenticationView = authenticationView;
        this.policy = policy;
        this.documents = documents;
    }

    public IdentityView inspect(Authentication auth, HttpServletRequest request) {
        boolean active = auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
        return new IdentityView(lab.role(), active, active ? auth.getName() : null,
                active ? auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList() :
                        List.of(),
                active ? accountAuthorities(auth) : List.of(),
                request.getSession(false) != null, active ? auth.getClass().getSimpleName() : null,
                authenticationView.loginUrl(request), entry.portalUrl(), lab.endpoints().baseline().toString(),
                lab.endpoints().contexa().toString(),
                documents.hash(documents.write(policy.rules())),
                authenticationView.inspect(active ? auth : null, request));
    }

    private List<String> accountAuthorities(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UnifiedCustomUserDetails principal) {
            return principal.getOriginalAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).sorted().toList();
        }
        return null;
    }
}
