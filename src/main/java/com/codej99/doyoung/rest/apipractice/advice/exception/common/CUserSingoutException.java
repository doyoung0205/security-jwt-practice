package com.codej99.doyoung.rest.apipractice.advice.exception.common;

public class CUserSingoutException extends RuntimeException {
    public CUserSingoutException(String msg, Throwable t) {
        super(msg, t);
    }

    public CUserSingoutException(String msg) {
        super(msg);
    }

    public CUserSingoutException() {
        super();
    }
}
