package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes.Field;
import io.contexa.showcase.business.work.BusinessRequestAttributes;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The business module copies the engine's resource attribute names because it does not depend on Contexa
 * (BusinessRequestAttributes): each copy is the engine's own name, the target's scope of finding 7 of the v21 plan
 * included.
 */
class BusinessRequestAttributesContractTest {

    @Test
    void everyResourceAttributeTheBusinessWritesIsTheEnginesOwnName() {
        assertThat(BusinessRequestAttributes.RESOURCE_BUSINESS_LABEL)
                .isEqualTo(Field.RESOURCE_BUSINESS_LABEL.canonicalAttributeKey());
        assertThat(BusinessRequestAttributes.RESOURCE_SENSITIVITY)
                .isEqualTo(Field.RESOURCE_SENSITIVITY.canonicalAttributeKey());
        assertThat(BusinessRequestAttributes.SENSITIVE_RESOURCE)
                .isEqualTo(Field.SENSITIVE_RESOURCE.canonicalAttributeKey());
        assertThat(BusinessRequestAttributes.RESOURCE_AUTHOR_TEXT)
                .isEqualTo(Field.RESOURCE_AUTHOR_TEXT.canonicalAttributeKey());
        assertThat(BusinessRequestAttributes.REQUEST_ITEMS).isEqualTo(Field.REQUEST_ITEMS.canonicalAttributeKey());
        assertThat(BusinessRequestAttributes.RESOURCE_SCOPE).isEqualTo(Field.RESOURCE_SCOPE.canonicalAttributeKey());
    }
}
