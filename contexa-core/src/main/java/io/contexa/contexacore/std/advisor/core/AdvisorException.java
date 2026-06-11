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
package io.contexa.contexacore.std.advisor.core;

public class AdvisorException extends RuntimeException {
    
    private final boolean blocking;
    private final String domain;
    private final String advisorName;

    public static AdvisorException blocking(String domain, String advisorName, String message) {
        return new AdvisorException(domain, advisorName, message, true);
    }

    public static AdvisorException nonBlocking(String domain, String advisorName, String message) {
        return new AdvisorException(domain, advisorName, message, false);
    }
    
    private AdvisorException(String domain, String advisorName, String message, boolean blocking) {
        super(message);
        this.domain = domain;
        this.advisorName = advisorName;
        this.blocking = blocking;
    }
    
    public boolean isBlocking() {
        return blocking;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public String getAdvisorName() {
        return advisorName;
    }
}