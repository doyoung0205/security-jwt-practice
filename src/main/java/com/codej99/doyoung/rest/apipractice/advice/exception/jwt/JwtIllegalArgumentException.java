package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;

import io.jsonwebtoken.JwtException;

public class JwtIllegalArgumentException extends JwtException {

    public JwtIllegalArgumentException(String message) {
        super(message);
    }
    public JwtIllegalArgumentException(String message, Throwable cause) {
        super(message, cause);
    }

}
