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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

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

    /** Two requests for two records differ in a value only, and no record may keep a value. */
    @Test
    void aQueryReferenceTellsOneQueryFromAnotherAndHoldsNoValue() {
        String reference = RequestFactRedaction.queryReference("id=4831&pin=1234");

        assertThat(reference).startsWith("qry-").hasSize(28).doesNotContain("4831").doesNotContain("1234");
        assertThat(RequestFactRedaction.queryReference("id=4831&pin=1234")).isEqualTo(reference);
        assertThat(RequestFactRedaction.queryReference("id=4832&pin=1234")).isNotEqualTo(reference);
        assertThat(RequestFactRedaction.queryReference(null)).isNull();
        assertThat(RequestFactRedaction.queryReference(" ")).isNull();
    }

    /** A short value could be tried against a plain digest of the query: the reference is keyed by the process. */
    @Test
    void aQueryReferenceIsNoPlainDigestOfTheQuery() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("pin=1234".getBytes(StandardCharsets.UTF_8));

        assertThat(RequestFactRedaction.queryReference("pin=1234"))
                .isNotEqualTo("qry-" + HexFormat.of().formatHex(digest, 0, 12));
    }
}
