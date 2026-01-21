package io.contexa.contexaidentity.service;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class MfaSupportService { 

    private final UserRepository userRepository;

    public Set<AuthType> getAvailableMfaFactorsForUser(String username) {
        Assert.hasText(username, "Username cannot be empty for fetching available MFA factors");
                return EnumSet.noneOf(AuthType.class);
    }
}