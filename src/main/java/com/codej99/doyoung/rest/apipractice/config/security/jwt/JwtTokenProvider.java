package com.codej99.doyoung.rest.apipractice.config.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/*
 *  Jwt 토큰 생성 및 유효성 검증을 하는 컴포넌트입니다. Jwt 는 여러가지 암호화 알고리즘을 제공하며 알고리즘 (SignatureAlgorithm.XXX)과 비밀키(secretKey)를 가지고 토큰을 생성하게 됩니다.
 *  이때 claim 정보에는 토큰에 부가적으로 실어 보낼 정보를 세팅할 수 있습니다.
 *  claim 정보에 회원을 구분할 수 있는 값을 세팅하였다가 토큰이 들어오면 해당 값으로 회원을 구분하여 리소스를 제공하면 됩니다. 그리고 Jwt 토큰에는 expire 시간을 세팅할 수 있습니다.
 *  토큰 발급 후 일정 시간 이후에는 토큰을 만료시키는 데 사용할 수 있습니다.
 *  resolveToken 메서드는 Http request header 에 세팅된 토큰 값을 가져와 유효성을 체크합니다.
 *  제한된 리소스를 요청할 때 Http header 에 토큰을 세팅하여 호출하면 유효성을 검증하여 사용자 인증을 할 수 있습니다.
 * */





@RequiredArgsConstructor
@Component
@Log
public class JwtTokenProvider { // JWT 토큰을 생성 및 검증 모듈
    @Value("spring.jwt.secret")
    private String secretKey;
    private long tokenValidMilisecond = 1000L * 60 * 60; // 1시간만 토큰 유효
    private final UserDetailsService userDetailsService;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // Jwt 토큰 생성
    public String createToken(String userPk, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(userPk);
        claims.put("roles", roles);
        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(now) // 토큰 발행일자
                .setExpiration(new Date(now.getTime() + tokenValidMilisecond)) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secret값 세팅
                .compact();
    }

    // Jwt 토큰으로 인증 정보를 조회
    public Authentication getAuthentication(String token) {
        final UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // Jwt 토큰에서 회원 구별 정보 추출
    public String getUserPk(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    // Request 의 Header 에서 token 파싱 : "X-AUTH-TOKEN: jwt 토큰"
    public String resolveToken(HttpServletRequest req) {
        return req.getHeader("X-AUTH-TOKEN");
    }

    // Jwt 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}