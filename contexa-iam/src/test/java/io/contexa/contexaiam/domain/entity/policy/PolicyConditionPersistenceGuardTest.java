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
package io.contexa.contexaiam.domain.entity.policy;

import io.contexa.contexaiam.security.xacml.pdp.evaluation.UnsafePolicyExpressionException;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyConditionPersistenceGuardTest {

    @Test
    void guardRunsBeforeInsertAndUpdate() throws NoSuchMethodException {
        Method guard = PolicyCondition.class.getDeclaredMethod("validateExpression");

        assertThat(guard.getAnnotation(PrePersist.class)).isNotNull();
        assertThat(guard.getAnnotation(PreUpdate.class)).isNotNull();
    }

    @Test
    void dangerousExpressionIsNeverPersisted() {
        PolicyCondition condition = PolicyCondition.builder()
                .expression("T(java.lang.Runtime).getRuntime().exec('calc') != null").build();

        assertThatThrownBy(condition::validateExpression).isInstanceOf(UnsafePolicyExpressionException.class);
    }

    @Test
    void safeExpressionIsPersisted() {
        PolicyCondition condition = PolicyCondition.builder().expression("isAuthenticated()").build();

        assertThatCode(condition::validateExpression).doesNotThrowAnyException();
    }
}
