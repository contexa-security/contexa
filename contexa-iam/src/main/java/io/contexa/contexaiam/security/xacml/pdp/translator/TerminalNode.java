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
package io.contexa.contexaiam.security.xacml.pdp.translator;

import lombok.Getter;

import java.util.Collections;
import java.util.Set;

@Getter
public class TerminalNode implements ExpressionNode {

    private final String description;
    private final String authority;
    private final boolean authenticationRequired; 

    public TerminalNode(String description, String authority, boolean authenticationRequired) {
        this.description = description;
        this.authority = authority;
        this.authenticationRequired = authenticationRequired;
    }

    public TerminalNode(String description, boolean authenticationRequired) {
        this(description, null, authenticationRequired);
    }

    public TerminalNode(String description) {
        this(description, null, false); 
    }

    @Override
    public Set<String> getRequiredAuthorities() {
        return authority != null ? Set.of(authority) : Collections.emptySet();
    }

    @Override
    public boolean requiresAuthentication() {
        return this.authenticationRequired;
    }

    @Override
    public String getConditionDescription() {
        return description;
    }
}

