package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;


import io.jsonwebtoken.JwtException;

public class JwtRuntimeException extends JwtException {

    public JwtRuntimeException(String message) {
        super(message);
    }

    public JwtRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }
}
