package io.contexa.demo.readiness.service;

import io.contexa.demo.readiness.dto.RuntimeMode;

public interface RuntimeSecurityQuery {

    RuntimeMode inspect();
}
