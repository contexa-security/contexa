package io.contexa.demo.identity.dto;

public record AccessObservation(
        String username,
        String requirement,
        String source
) {

}
