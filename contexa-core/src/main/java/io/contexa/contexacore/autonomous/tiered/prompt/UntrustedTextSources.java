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
package io.contexa.contexacore.autonomous.tiered.prompt;

/**
 * The sources an UNTRUSTED TEXT line names (W3-6, N-INJ-1, N-INJ-3, N-INJ-4): the one list the render draws them by
 * and the prompt inspector compares them by (R1b-3).
 */
public final class UntrustedTextSources {

    /** The document description an outside author wrote. */
    public static final String DOCUMENT_DESCRIPTION = "document description (external author)";
    /** The host's business label of the target, its free text (a document title, an export's description), N-INJ-3. */
    public static final String BUSINESS_LABEL = "business label (host text)";
    /** The host's resource category when it is not a token, its free text (N-INJ-4). */
    public static final String RESOURCE_CATEGORY = "resource category (host text)";
    /** The request's body. */
    public static final String REQUEST_BODY = "request body (requester)";
    /** A sentence of outside threat knowledge. */
    public static final String THREAT_KNOWLEDGE = "threat knowledge (outside feed)";
    /** An anomaly signal the requester claims. */
    public static final String ANOMALY_SIGNAL_HEADER = "anomaly signal header (unverified requester claim)";
    /** The host's text of a temporary elevation's reason. */
    public static final String ELEVATION_REASON = "elevation reason (host text)";
    /** The requester's user agent the device line cannot name. */
    public static final String USER_AGENT = "user agent (requester)";
    /** The request's path with its variables. */
    public static final String REQUEST_PATH = "request path (requester)";
    /** The session's earlier request paths. */
    public static final String SESSION_REQUEST_PATHS = "session request paths (requester)";
    /** A ticket the requester names. */
    public static final String CLAIMED_TICKET = "ticket named by the requester (requester)";
    /** What the caller passed to the protected method, as the publisher summarised it (v21, A2-8). */
    public static final String CALL_ARGUMENTS = "call arguments (requester)";
    /** The target of a past record or a past denied decision: path variables a requester wrote (v21, A3-5). */
    public static final String PAST_RECORD_TARGET = "past record target (requester)";
    /** The objective of a delegation in the words it was written in (v21, A2-5). */
    public static final String DELEGATION_OBJECTIVE = "delegation objective (host text)";
    /**
     * A stored text of the validated case memory: an earlier analysis' summary, a threat signal's summary or matched
     * threat knowledge, written outside this request (v21, B3-3).
     */
    public static final String VALIDATED_CASE_MEMORY = "validated case memory (stored text)";
    /**
     * The sentence of a tool's output in which the host found an argument value of the request for the first time,
     * quoted by the host (v21, CQ-1): the output was written outside this request, and may carry any instruction.
     */
    public static final String TOOL_OUTPUT_EXCERPT = "tool output excerpt (host-quoted)";

    private UntrustedTextSources() {
    }
}
