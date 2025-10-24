package io.contexa.contexaiam.domain.dto;

import lombok.Data;

@Data
public class UserListDto {
    private Long id;
    private String name;
    private String username;
    private boolean mfaEnabled;
    private int groupCount;
    private int roleCount;
}
