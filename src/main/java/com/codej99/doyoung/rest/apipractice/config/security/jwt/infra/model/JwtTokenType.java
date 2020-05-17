package com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.internal.build.AllowPrintStacktrace;

@AllowPrintStacktrace
@NoArgsConstructor
@Getter
public enum JwtTokenType {
    REFRESH, ACCESS
}
