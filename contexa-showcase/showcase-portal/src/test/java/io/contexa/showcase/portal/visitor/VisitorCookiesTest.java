package io.contexa.showcase.portal.visitor;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** P2-DB-01: a forged or altered visitor cookie is refused; only the identifier hash is stored. */
class VisitorCookiesTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String OTHER_KEY = Base64.getEncoder().encodeToString("k".repeat(32).getBytes());

    @Test
    void anIssuedCookieVerifiesAndAnotherKeysCookieDoesNot() {
        VisitorCookies cookies = new VisitorCookies(KEY);
        String value = cookies.issue();

        assertThat(cookies.verify(value)).isPresent();
        assertThat(new VisitorCookies(OTHER_KEY).verify(value)).as("signed with another key").isEmpty();
    }

    @Test
    void alteredOrMalformedValuesAreRefused() {
        VisitorCookies cookies = new VisitorCookies(KEY);
        String value = cookies.issue();
        String id = value.substring(0, value.indexOf('.'));
        String signature = value.substring(value.indexOf('.') + 1);
        String otherId = cookies.issue().substring(0, value.indexOf('.'));

        assertThat(cookies.verify(otherId + "." + signature)).as("identifier swapped").isEmpty();
        assertThat(cookies.verify(id + "." + signature.substring(1) + "A")).as("signature altered").isEmpty();
        assertThat(cookies.verify(id)).isEmpty();
        assertThat(cookies.verify("." + signature)).isEmpty();
        assertThat(cookies.verify("not base64!." + signature)).isEmpty();
        assertThat(cookies.verify(null)).isEmpty();
    }

    @Test
    void theStoredValueIsAHashOfTheIdentifier() {
        VisitorCookies cookies = new VisitorCookies(KEY);
        String id = cookies.verify(cookies.issue()).orElseThrow();

        assertThat(VisitorCookies.hash(id)).hasSize(64).doesNotContain(id);
    }

    @Test
    void aMissingOrShortKeyIsRefused() {
        assertThatThrownBy(() -> new VisitorCookies("")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new VisitorCookies(Base64.getEncoder().encodeToString(new byte[8])))
                .isInstanceOf(IllegalStateException.class);
    }
}
