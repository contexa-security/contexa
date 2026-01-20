package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import lombok.Data;
import org.antlr.v4.runtime.misc.NotNull;


@Data
public class InitiateManagementRequestDto {

    @NotNull
    private Long subjectId;


    private String subjectType; 
}
