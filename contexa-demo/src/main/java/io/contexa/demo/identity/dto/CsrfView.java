package io.contexa.demo.identity.dto;

public record CsrfView(
        String token,
        String headerName,
        String parameterName
) {

}
