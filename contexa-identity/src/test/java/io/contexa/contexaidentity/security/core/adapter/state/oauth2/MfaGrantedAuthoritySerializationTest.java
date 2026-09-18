package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.MfaGrantedAuthority;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.MfaGrantedAuthorityMixin;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class MfaGrantedAuthoritySerializationTest {
    final ObjectMapper mapper = new ObjectMapper().addMixIn(MfaGrantedAuthority.class, MfaGrantedAuthorityMixin.class);

    @ParameterizedTest @ValueSource(strings = {"role", "authority"})
    void readsBothPersistedFieldNames(String field) throws Exception {
        String json = "{\"@class\":\"" + MfaGrantedAuthority.class.getName() + "\",\"" + field + "\":\"MFA_VERIFIED\"}";
        assertThat(mapper.readValue(json, MfaGrantedAuthority.class).getAuthority()).isEqualTo("MFA_VERIFIED");
    }
    @Test void currentWriterAndReaderRoundTrip() throws Exception {
        MfaGrantedAuthority authority = new MfaGrantedAuthority("MFA_VERIFIED");
        assertThat(mapper.readValue(mapper.writeValueAsString(authority), MfaGrantedAuthority.class)).isEqualTo(authority);
    }
}
