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
package io.contexa.contexaiam.security.xacml.pap.controller;

import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * The policy list lives in the policy center (its list tab shows every policy with its approval state); the old list
 * page was removed, so its address leads there instead of rendering a page that no longer exists.
 */
@ExtendWith(MockitoExtension.class)
class PolicyControllerListTest {

    @Mock
    private PolicyService policyService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private MessageSource messageSource;

    @Test
    @DisplayName("The old policy list address leads to the policy center's list")
    void theOldListAddressLeadsToThePolicyCentersList() {
        PolicyController controller = new PolicyController(policyService, modelMapper, messageSource);

        assertThat(controller.listPolicies()).isEqualTo("redirect:/contexa/admin/policy-center?tab=list");
        verifyNoInteractions(policyService, modelMapper);
    }
}
