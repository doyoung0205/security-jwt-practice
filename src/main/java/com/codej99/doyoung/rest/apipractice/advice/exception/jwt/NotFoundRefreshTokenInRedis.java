package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;

import io.jsonwebtoken.JwtException;

public class NotFoundRefreshTokenInRedis extends JwtException {

    public NotFoundRefreshTokenInRedis(String message) {
        super(message);
    }

    public NotFoundRefreshTokenInRedis(String message, Throwable cause) {
        super(message, cause);
    }
}
