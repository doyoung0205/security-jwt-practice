package com.codej99.doyoung.rest.apipractice.config.security.jwt.domain;

import com.codej99.doyoung.rest.apipractice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.domain.JwtConfigConstants.*;
import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.domain.JwtConfigConstants.JWT_SECRET_KEY;

public class JwtTokenUtil {

    //Jwt 토큰 생성 with User and now
    public static String createToken(User user, LocalDateTime now, LocalDateTime expiresAt) {

        Claims claims = createClaims(user);
        // TODO accessToken 에다가 Barer prefix 붙이기

        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant())) // 토큰 발행 일자
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant())) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }

    //Jwt 토큰 생성 with User and now
    public static String createToken(final User user) {

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime expiresAt = JwtTokenUtil.getAccessTokenExpiresAt(now);

        Claims claims = createClaims(user);

        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant())) // 토큰 발행 일자
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant())) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }

    private static Claims createClaims(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUid());

        claims.put("msrl", user.getMsrl());
        claims.put("password", user.getPassword());
        claims.put("roles", user.getRoles());
        claims.put("name", user.getName());
        return claims;
    }

    public static LocalDateTime getAccessTokenExpiresAt(LocalDateTime now) {
        return now.plusMinutes(ACCESS_TOKEN_VALIDITY);
    }

    public static LocalDateTime getRefreshTokenExpiresAt(LocalDateTime now) {
        return now.plusWeeks(REFRESH_TOKEN_VALIDITY);
    }

}
