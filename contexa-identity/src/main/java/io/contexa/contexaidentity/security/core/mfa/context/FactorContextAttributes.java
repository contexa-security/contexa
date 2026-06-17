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
package io.contexa.contexaidentity.security.core.mfa.context;

public final class FactorContextAttributes {

    private FactorContextAttributes() {
        throw new AssertionError("Utility class cannot be instantiated");
    }

    public static final class Timestamps {
        public static final String PRIMARY_AUTH_COMPLETED_AT = "primaryAuthCompletedAt";
        public static final String CHALLENGE_INITIATED_AT = "challengeInitiatedAt";
        public static final String VERIFICATION_STARTED_AT = "verificationStartedAt";
        public static final String FACTOR_COMPLETED_AT = "factorCompletedAt";
        public static final String MFA_COMPLETED_AT = "mfaCompletedAt";
        public static final String LAST_ATTEMPT_AT = "lastAttemptAt";
        public static final String LAST_FAILED_AT = "lastFailedAt";
        public static final String LOGIN_TIMESTAMP = "loginTimestamp";
        public static final String FACTOR_SELECTED_AT = "factorSelectedAt";

        private Timestamps() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class UserInfo {
        public static final String USERNAME = "username";
        public static final String USER_ID = "userId";
        public static final String EMAIL = "email";
        public static final String USER_OTT_PREFERENCE = "userOttPreference";

        private UserInfo() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class FactorInfo {
        public static final String CURRENT_PROCESSING_FACTOR = "currentProcessingFactor";
        public static final String FACTOR_TYPE = "factorType";
        public static final String SELECTED_FACTOR = "selectedFactor";
        public static final String OTT_CODE_SENT = "ottCodeSent";
        public static final String OTT_DELIVERY_METHOD = "ottDeliveryMethod";
        public static final String PASSKEY_TYPE = "passkeyType";

        private FactorInfo() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class Policy {
        public static final String AVAILABLE_FACTORS = "availableFactors";
        public static final String COMPLETED_FACTORS = "completedFactors";
        public static final String REQUIRED_FACTORS = "requiredFactors";
        public static final String RISK_SCORE = "riskScore";
        public static final String AI_RISK_SCORE = "aiRiskScore";
        public static final String ZERO_TRUST_ACTION = "zeroTrustAction";

        private Policy() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class CompletionState {
        public static final String IS_COMPLETED = "isCompleted";
        public static final String NEEDS_FACTOR_SELECTION = "needsFactorSelection";
        public static final String SELECT_FACTOR_ATTEMPT_COUNT = "selectFactorAttemptCount";

        private CompletionState() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class Retry {
        public static final String RETRY_COUNT = "retryCount";
        public static final String RETRY_LIMIT = "retryLimit";

        private Retry() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class FlowMetadata {
        public static final String MFA_SESSION_ID = "mfaSessionId";
        public static final String FLOW_TYPE_NAME = "flowTypeName";
        public static final String FLOW_ORDER = "flowOrder";

        private FlowMetadata() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class DeviceAndSession {
        public static final String DEVICE_TRUSTED = "deviceTrusted";
        public static final String REMEMBER_ME = "rememberMe";
        public static final String DEVICE_ID = "deviceId";
        public static final String CLIENT_IP = "clientIp";
        public static final String USER_AGENT = "userAgent";

        private DeviceAndSession() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class MessageAndReason {
        public static final String MESSAGE = "message";
        public static final String REASON = "reason";
        public static final String BLOCK_REASON = "blockReason";

        private MessageAndReason() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class StateControl {
        public static final String BLOCKED = "blocked";
        public static final String MFA_DECISION_TYPE = "mfaDecisionType";
        public static final String NEXT_EVENT_RECOMMENDATION = "nextEventRecommendation";
        public static final String ERROR_EVENT_RECOMMENDATION = "errorEventRecommendation";
        public static final String USER_INFO = "userInfo";
        public static final String FAILURE_COUNT = "failureCount";
        public static final String VERIFICATION_SUCCESS_COUNT = "verificationSuccessCount";
        public static final String FACTOR_SELECTION_TIMEOUT_MS = "factorSelectionTimeoutMs";

        private StateControl() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }

    public static final class Idempotency {
        public static final String LAST_REQUEST_ID = "idempotency.lastRequestId";
        public static final String LAST_EVENT = "idempotency.lastEvent";
        public static final String LAST_EVENT_ACCEPTED = "idempotency.lastEventAccepted";
        public static final String LAST_EVENT_STATE = "idempotency.lastEventState";
        public static final String LAST_EVENT_VERSION = "idempotency.lastEventVersion";

        private Idempotency() {
            throw new AssertionError("Utility class cannot be instantiated");
        }
    }
}
