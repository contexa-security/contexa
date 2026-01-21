package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.MatrixFilter;
import io.contexa.contexaiam.admin.web.monitoring.dto.PermissionMatrixDto;

public interface PermissionMatrixService {
    
    PermissionMatrixDto getPermissionMatrix();

    PermissionMatrixDto getPermissionMatrix(MatrixFilter filter);
}