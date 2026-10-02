package io.contexa.demo.security.policy.dto;

public record PolicyRule(
        String pattern,
        String requirement
) {

}
