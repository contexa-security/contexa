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
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;

@RequiredArgsConstructor
public class PermissionTargetPermissionEvaluator extends AbstractDomainPermissionEvaluator {

    private final ApplicationContext applicationContext;

    @Override
    protected String domain() {
        return "PERMISSION";
    }

    @Override
    protected String repositoryBeanName() {
        return "permissionRepository";
    }

    @Override
    protected ApplicationContext getApplicationContext() {
        return applicationContext;
    }
}
