/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Q-11 (PR-59, PR-64): what of a request may be kept. */
class RequestFactRedactionTest {

    private static final String LIVE_SESSION = "F7A9C31D0B2E4F6A8C1D3E5F7A9B0C2D";

    @Test
    void aSessionReferenceTellsTheSameSessionAndOpensNothing() {
        String reference = RequestFactRedaction.sessionReference(LIVE_SESSION);

        assertThat(reference).startsWith("sid-").hasSize(28).doesNotContain(LIVE_SESSION);
        assertThat(RequestFactRedaction.sessionReference(" " + LIVE_SESSION + " ")).isEqualTo(reference);
        assertThat(RequestFactRedaction.sessionReference("another-session")).isNotEqualTo(reference);
    }

    /** A sealed decision replayed names its session by the reference it kept, and the reference must not move. */
    @Test
    void aReferenceStaysAsItIs() {
        String reference = RequestFactRedaction.sessionReference(LIVE_SESSION);

        assertThat(RequestFactRedaction.sessionReference(reference)).isEqualTo(reference);
    }

    @Test
    void aSessionIdThatStartsLikeAReferenceIsStillASessionId() {
        // An application names its own sessions: only the exact shape of a reference is one.
        String applicationSession = "sid-7f3a9c2e-live-session-of-the-application";

        assertThat(RequestFactRedaction.sessionReference(applicationSession))
                .doesNotContain("live-session").hasSize(28);
        assertThat(RequestFactRedaction.sessionReference("sid-ABCDEF0123456789ABCDEF01")).hasSize(28)
                .isNotEqualTo("sid-ABCDEF0123456789ABCDEF01");
    }

    @Test
    void noSessionHasNoReference() {
        assertThat(RequestFactRedaction.sessionReference(null)).isNull();
        assertThat(RequestFactRedaction.sessionReference("  ")).isNull();
    }

    @Test
    void aQueryKeepsItsNamesInOrderAndNoValue() {
        assertThat(RequestFactRedaction.queryNames("pin=1234&newPwd=s3cret&ssn=900101&token=abc.def"))
                .isEqualTo("pin&newPwd&ssn&token");
        assertThat(RequestFactRedaction.queryNames("id=1&id=2")).isEqualTo("id&id");
        assertThat(RequestFactRedaction.queryNames("a=b=c")).isEqualTo("a");
        assertThat(RequestFactRedaction.queryNames("empty=")).isEqualTo("empty");
    }

    /** A part without a name may be the secret itself: a signed link's token, or a value sent as the whole query. */
    @Test
    void aPartThatMayBeAValueIsLeftOut() {
        assertThat(RequestFactRedaction.queryNames("d41d8cd98f00b204e9800998ecf8427e")).isNull();
        assertThat(RequestFactRedaction.queryNames("=value")).isNull();
        assertThat(RequestFactRedaction.queryNames("&&")).isNull();
        assertThat(RequestFactRedaction.queryNames("page=2&d41d8cd98f00b204")).isEqualTo("page");
    }

    @Test
    void noQueryHasNoNames() {
        assertThat(RequestFactRedaction.queryNames(null)).isNull();
        assertThat(RequestFactRedaction.queryNames(" ")).isNull();
    }

    private static final String SECRET = "s3cr3t-value";
    private static final String SIGNED_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl";

    /** A person confirms what the agent asks, but what opens something is not for them to read, or for the record. */
    @ParameterizedTest
    @ValueSource(strings = {
            "token", "TOKEN", "Token", "access_token", "accessToken", "accesstoken", "refresh-token", "id_token", "token_value",
            "api_key", "apiKey", "apikey", "x-api-key", "X-API-KEY", "API-KEY", "secret", "client_secret", "clientSecret",
            "secret_key", "password", "PASSWORD", "newPassword", "new_password", "newpassword", "user[password]", "user.password",
            "passwd", "pwd", "newPwd", "newpwd", "pin", "PIN", "cardPin", "card_pin", "otp", "ssn", "user_ssn", "cvv", "cvc",
            "session", "sessionId", "session_id", "JSESSIONID", "sid", "signature", "sig", "authorization", "auth", "auth_code",
            "credential", "credentials", "cookie", "private_key", "access_key", "passphrase", "passcode",
            "%74oken", "pass%77ord", "api%5Fkey", "api%2Dkey", "user%5Bpassword%5D", "%70%69%6E", "token%00", "to%zzken"})
    void theValueOfANameThatSaysSecretIsMasked(String name) {
        String target = RequestFactRedaction.readableTarget("/api/reports?format=zip&" + name + "=" + SECRET + "&page=2");

        assertThat(target).doesNotContain(SECRET).startsWith("/api/reports?format=zip&" + name + "=")
                .endsWith("&page=2");
    }

    /** A value can give itself away, whatever the name in front of it. */
    @ParameterizedTest
    @ValueSource(strings = {
            SIGNED_TOKEN, "Bearer%20abcdef0123456789", "bearer+abcdef0123456789", "sk-abcdefghij0123456789",
            "AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "xoxb-1234567890-abcdefghij",
            "900101-1234567", "123-45-6789", "-----BEGIN%20PRIVATE%20KEY-----",
            "https%3A%2F%2Fa.test%2Fcb%3Ftoken%3Ds3cr3t-value",
            "https%253A%252F%252Fa.test%252Fcb%253Ftoken%253Ds3cr3t-value",
            "%2Fcb%3Fa%3D1%26password%3Ds3cr3t-value"})
    void aValueThatLooksLikeASecretIsMasked(String value) {
        String target = RequestFactRedaction.readableTarget("/api/reports?next=" + value);

        assertThat(target).isEqualTo("/api/reports?next=[MASKED]");
    }

    @Test
    void everySeparatorOfAQueryIsReadAndKept() {
        assertThat(RequestFactRedaction.readableTarget("/a?format=zip;token=" + SECRET + "&page=2"))
                .isEqualTo("/a?format=zip;token=[MASKED]&page=2");
        assertThat(RequestFactRedaction.readableTarget("/a?token=" + SECRET + "&token=" + SECRET))
                .isEqualTo("/a?token=[MASKED]&token=[MASKED]");
        assertThat(RequestFactRedaction.readableTarget("/a?token=a=b=" + SECRET)).isEqualTo("/a?token=[MASKED]");
        assertThat(RequestFactRedaction.readableTarget("/a?" + SIGNED_TOKEN)).as("a value sent as the whole query")
                .isEqualTo("/a?[MASKED]");
        assertThat(RequestFactRedaction.readableTarget("/a?page=2&" + SIGNED_TOKEN)).isEqualTo("/a?page=2&[MASKED]");
    }

    /** The path can carry them too. */
    @Test
    void thePathIsReadAsWell() {
        assertThat(RequestFactRedaction.readableTarget("/a;jsessionid=" + SECRET + "?format=zip"))
                .isEqualTo("/a;jsessionid=[MASKED]?format=zip");
        assertThat(RequestFactRedaction.readableTarget("/a;v=1;token=" + SECRET + "/b"))
                .isEqualTo("/a;v=1;token=[MASKED]/b");
        assertThat(RequestFactRedaction.readableTarget("/reset/" + SIGNED_TOKEN + "/confirm"))
                .isEqualTo("/reset/[MASKED]/confirm");
    }

    /** What a person is asked to confirm stays readable: the point is that they see it. */
    @ParameterizedTest
    @ValueSource(strings = {
            "/api/exports", "/api/exports?format=zip", "/api/exports?format=zip&project=HX-310&documents=40",
            "/api/search?q=hello%20world&author=bob&spinner=1&pinned=true&keyword=x&tokens=3&sessions=2&secretary=kim",
            "/api/a?b", "/api/a?", "/api/a?&&", "/api/a?=", "/api/orders/2026-11-05", "/api/orders/123456-1234"})
    void whatIsNoSecretStaysAsItIs(String target) {
        assertThat(RequestFactRedaction.readableTarget(target)).isEqualTo(target);
    }

    @Test
    void noTargetStaysNone() {
        assertThat(RequestFactRedaction.readableTarget(null)).isNull();
        assertThat(RequestFactRedaction.readableTarget("")).isEmpty();
    }
}
