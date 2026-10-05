package io.contexa.showcase.workload.plain.security;

import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

/**
 * Sign-in accounts of the plain controls: one per run principal, with the role of the employee it plays.
 */
public class PlainUserDetailsService implements UserDetailsService {

    private final WorkDatabase database;

    public PlainUserDetailsService(WorkDatabase database) {
        this.database = database;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        List<UserDetails> users = database.jdbc().query("""
                        select u.username, u.password_hash, e.role_key
                          from plain_user u
                          join run_principal p on p.username = u.username
                          join employee e on e.employee_key = p.employee_key
                         where u.username = :username""",
                new MapSqlParameterSource("username", username),
                (rs, n) -> User.withUsername(rs.getString(1))
                        .password(rs.getString(2))
                        .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + rs.getString(3))))
                        .build());
        return users.stream().findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("Unknown plain control user"));
    }
}
