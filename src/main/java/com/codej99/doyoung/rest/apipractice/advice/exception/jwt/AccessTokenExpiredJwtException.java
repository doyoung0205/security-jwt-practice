package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;

public class AccessTokenExpiredJwtException extends JwtException {

    public AccessTokenExpiredJwtException(String message) {
        super(message);
    }

    public AccessTokenExpiredJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
