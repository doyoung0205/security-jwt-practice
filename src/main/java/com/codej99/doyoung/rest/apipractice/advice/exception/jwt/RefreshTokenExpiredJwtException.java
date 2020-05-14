package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;

import io.jsonwebtoken.JwtException;

public class RefreshTokenExpiredJwtException extends JwtException {

    public RefreshTokenExpiredJwtException(String message) {
        super(message);
    }

    public RefreshTokenExpiredJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
