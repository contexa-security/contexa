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
package io.contexa.contexacore.autonomous.context.decision;

/**
 * Why a company record does not cover a request, or why the company's policy is not satisfied (W2-5). The order is
 * the order in which a record's failures are stated, the first one being the reason the policy names.
 */
public enum PolicyReason {

    /** No record covers the work: none exists, or the one there is not an approved record of this work. */
    NO_RECORD,
    /** The record covers another target. */
    OTHER_TARGET,
    /** The request falls outside the record's validity. */
    EXPIRED,
    /** The record's decision was recorded after the request. */
    LATE,
    /** The request alone asks for more items than the record allows. */
    OVER_LIMIT,
    /** The request together with what the session already did under the record asks for more than it allows. */
    CUMULATIVE,
    /** A ticket covers the work, but the policy's exception also needs the requester on call. */
    TICKET_WITHOUT_ON_CALL;

    /** The reason code: {@code POLICY_NOT_SATISFIED_LATE}. */
    public String code() {
        return "POLICY_NOT_SATISFIED_" + name();
    }
}
