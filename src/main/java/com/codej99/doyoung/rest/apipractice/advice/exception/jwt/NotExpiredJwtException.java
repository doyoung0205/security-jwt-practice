package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;

import io.jsonwebtoken.JwtException;

public class NotExpiredJwtException extends JwtException {

    public NotExpiredJwtException(String message) {
        super(message);
    }

    public NotExpiredJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
