package io.contexa.demo.identity.repository;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public interface AccountRepository {

    UserDetails find(String username);

    void seedPortalAccount(String username, String displayName, String hash, List<String> authorities);

    int enabledCount();
}
