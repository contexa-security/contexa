package io.contexa.demo.identity.repository;

import io.contexa.demo.identity.dto.IdentityAccount;

import java.util.List;

public interface NativeIdentitySource {

    String database();

    List<IdentityAccount> load(List<String> usernames);
}
