package io.contexa.demo.identity.service;

import io.contexa.demo.identity.repository.AccountRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@Profile("!contexa")
public class RepositoryUserDetailsService implements UserDetailsService {

    private final AccountRepository accounts;

    public RepositoryUserDetailsService(AccountRepository accounts) {
        this.accounts = accounts;
    }

    public UserDetails loadUserByUsername(String username) {
        return accounts.find(username);
    }
}
