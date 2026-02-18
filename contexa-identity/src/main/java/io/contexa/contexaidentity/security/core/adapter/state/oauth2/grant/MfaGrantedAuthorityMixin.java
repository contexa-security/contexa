package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import com.fasterxml.jackson.annotation.*;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class MfaGrantedAuthorityMixin {

    @JsonCreator
    MfaGrantedAuthorityMixin(@JsonProperty("role") String role) {
    }
}
