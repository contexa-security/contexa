package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;



@Data
@NoArgsConstructor
@AllArgsConstructor
public class AssignmentChangeDto {

    private List<Assignment> added = new ArrayList<>(); 
    private List<Long> removedGroupIds = new ArrayList<>(); 
    private List<Long> removedRoleIds = new ArrayList<>(); 

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Assignment {
        @NotNull
        private Long targetId;
        @NotBlank
        private String targetType;
        private LocalDateTime validUntil;
    }
}
