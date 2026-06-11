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
package io.contexa.contexaidentity.security.statemachine.exception;

public class MfaStateMachineExceptions {

    public static class InvalidFactorException extends RuntimeException {
        public InvalidFactorException(String message) {
            super(message);
        }
    }

    public static class StateMachineActionException extends RuntimeException {
        public StateMachineActionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class ChallengeGenerationException extends RuntimeException {
        public ChallengeGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class FactorVerificationException extends RuntimeException {
        public FactorVerificationException(String message) {
            super(message);
        }
    }

    public static class StateTransitionException extends RuntimeException {
        public StateTransitionException(String message) {
            super(message);
        }
    }

    public static class SessionExpiredException extends RuntimeException {
        public SessionExpiredException(String message) {
            super(message);
        }
    }

    public static class ConcurrencyException extends RuntimeException {
        public ConcurrencyException(String message) {
            super(message);
        }
    }
}