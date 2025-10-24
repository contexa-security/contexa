package io.contexa.contexaiam.admin.web.workflow.translator;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;

public interface BusinessPolicyTranslator {
    Policy translate(WizardContext context);
}
