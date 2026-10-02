package io.contexa.demo.identity.dto;

public record AuthenticationProgress(
        String state,
        String mfaState,
        String currentFactor,
        String resumeUrl
) {

}
