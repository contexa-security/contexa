package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import lombok.Builder;

import java.io.Serializable;
import java.util.Set;


@Builder
public record WizardContext(
        String contextId,
        String sessionTitle,
        String sessionDescription,

        
        Subject targetSubject,
        Set<Long> initialAssignmentIds,

        Set<Long> permissionIds,

        
        Set<Subject> subjects

) implements Serializable {

    private static final long serialVersionUID = 4L; 

    @Builder
    public record Subject(Long id, String type) implements Serializable {
        private static final long serialVersionUID = 1L;
    }
}