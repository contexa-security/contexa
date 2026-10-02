package io.contexa.demo.identity.repository.engine;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.demo.identity.dto.IdentityAccount;
import io.contexa.demo.identity.repository.NativeIdentitySource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Profile("contexa")
public class ContexaIdentitySource implements NativeIdentitySource {

    private final JdbcOperations jdbc;
    private final UserDetailsService users;

    public ContexaIdentitySource(@Qualifier("contexaJdbcTemplate") JdbcOperations jdbc,
            @Qualifier("unifiedUserDetailsService") UserDetailsService users) {
        this.jdbc = jdbc;
        this.users = users;
    }

    public String database() {
        return jdbc.queryForObject("select current_database()", String.class);
    }

    public List<IdentityAccount> load(List<String> names) {
        return names.stream().sorted().map(name -> {
            var details = (UnifiedCustomUserDetails) users.loadUserByUsername(name);
            var user = details.getAccount();
            return new IdentityAccount(user.getId(), user.getUsername(), user.getName(), user.getPassword(),
                    user.isEnabled(),
                    user.isAccountLocked(), user.isCredentialsExpired(), user.isExternalAuthOnly(),
                    user.getLockExpiresAt(),
                    details.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
        }).toList();
    }
}
