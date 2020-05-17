package com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.domain;

public class JwtConfigConstants {

    public static final int REFRESH_TOKEN_VALIDITY = 0;
    public static final int ACCESS_TOKEN_VALIDITY = 0;

    public static final String JWT_SECRET_KEY = "Z292bGVwZWxAJCY=";

    public static final String ACCESS_TOKEN_HEADER_NAME = "X-AUTH-TOKEN";
    public static final String REFRESH_TOKEN_HEADER_NAME = "REFRESH-X-AUTH-TOKEN";
    public static final String REDIS_SIGNOUT_PREFIX = "SIGN_OUT_";

    public static final String TOKEN_TYPE = "bearer";

}
