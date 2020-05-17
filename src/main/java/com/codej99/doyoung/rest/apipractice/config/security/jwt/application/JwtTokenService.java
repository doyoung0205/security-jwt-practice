package com.codej99.doyoung.rest.apipractice.config.security.jwt.application;

import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtResponseDto;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtTokenType;
import com.codej99.doyoung.rest.apipractice.entity.User;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;

public interface JwtTokenService {

    boolean validateAccessToken(final String accessToken);

    boolean validateRefreshToken(final String refreshToken);

    Authentication getAuthentication(final String token);

    String updateToken(final String token, final LocalDateTime expiresAt);

    JwtResponseDto initialize(final User user);

    void validateUpdateAccessToken(final String accessToken, final String refreshToken, final String id);

    Object updateRefreshToken(final String refreshToken);

}
