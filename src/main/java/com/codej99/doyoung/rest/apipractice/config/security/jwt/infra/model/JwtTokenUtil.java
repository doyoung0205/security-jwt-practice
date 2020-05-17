package com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model;

import com.codej99.doyoung.rest.apipractice.entity.User;
import io.jsonwebtoken.*;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtConfigConstants.*;
import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtConfigConstants.JWT_SECRET_KEY;

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

    public static Claims createClaims(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUid());

        claims.put("msrl", user.getMsrl());
        claims.put("password", user.getPassword());
        claims.put("roles", user.getRoles());
        claims.put("name", user.getName());
        return claims;
    }

    public static String getSubjectByToken(String token) {
        return getClaimsJws(token).getBody().getSubject();
    }

    public static Claims getClaimsByToken(String token) {
        return getClaimsJws(token).getBody();
    }

    public static Jws<Claims> getClaimsJws(String token) {
        return Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(token);
    }

    public static LocalDateTime getAccessTokenExpiresAt(LocalDateTime now) {
        return now.plusMinutes(ACCESS_TOKEN_VALIDITY);
    }

    public static LocalDateTime getRefreshTokenExpiresAt(LocalDateTime now) {
        return now.plusWeeks(REFRESH_TOKEN_VALIDITY);
    }

    // Request 의 Header 에서 token 파싱 : "X-AUTH-TOKEN: jwt 토큰"
    public static String getRequestAcessToken(HttpServletRequest req) {
        final String accessTokenFromHeader = req.getHeader(ACCESS_TOKEN_HEADER_NAME);

        if (StringUtils.isEmpty(accessTokenFromHeader)) {
            throw new MalformedJwtException("refresh token이 존재 하지 않습니다.");
        }

        if (!accessTokenFromHeader.startsWith(ACCESS_TOKEN_PREFIX)) {
            throw new MalformedJwtException("잘못된 ACCESS TOKEN 입니다.");
        }

        return accessTokenFromHeader.substring(ACCESS_TOKEN_PREFIX.length());
    }

    public static String getRequestRefreshToken(HttpServletRequest req) {
        final String refreshTokenFromHeader = req.getHeader(REFRESH_TOKEN_HEADER_NAME);

        if (StringUtils.isEmpty(refreshTokenFromHeader)) {
            throw new MalformedJwtException("refresh token이 존재 하지 않습니다.");
        }

        return refreshTokenFromHeader;
    }

}
