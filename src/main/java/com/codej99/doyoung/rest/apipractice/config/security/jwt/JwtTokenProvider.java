package com.codej99.doyoung.rest.apipractice.config.security.jwt;

import com.codej99.doyoung.rest.apipractice.entity.User;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/*
 *  Jwt 토큰 생성 및 유효성 검증을 하는 컴포넌트 입니다. Jwt 는 여러가지 암호화 알고리즘을 제공하며 알고리즘 (SignatureAlgorithm.XXX)과 비밀키(secretKey)를 가지고 토큰을 생성하게 됩니다.
 *  이때 claim 정보에는 토큰에 부가적으로 실어 보낼 정보를 세팅할 수 있습니다.
 *  claim 정보에 회원을 구분할 수 있는 값을 세팅하였다가 토큰이 들어오면 해당 값으로 회원을 구분하여 리소스를 제공하면 됩니다. 그리고 Jwt 토큰에는 expire 시간을 세팅할 수 있습니다.
 *  토큰 발급 후 일정 시간 이후에는 토큰을 만료시키는 데 사용할 수 있습니다.
 *  resolveToken 메서드는 Http request header 에 세팅된 토큰 값을 가져와 유효성을 체크합니다.
 *  제한된 리소스를 요청할 때 Http header 에 토큰을 세팅하여 호출하면 유효성을 검증하여 사용자 인증을 할 수 있습니다.
 * */


@RequiredArgsConstructor
@Component
@Log
public class JwtTokenProvider {
    public static final String CLAIMS_USER_KEY = "user";
    @Value("spring.jwt.secret")
    private String secretKey;

    private final long accessTokenValidMilisecond = 1000L * 60 * 30; // 30분
    private final long tokenValidMilisecond = 1000L * 60 * 60 * 24 * 14; // 2주

    private final String ACCESS_TOKEN_KEY = "X-AUTH-TOKEN";
    private final String REFRESH_TOKEN_KEY = "REFRESH-X-AUTH-TOKEN";


    private final UserDetailsService userDetailsService;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // Jwt 토큰 생성 with userPk, roles
    public String createToken(String userPk, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(userPk);
        claims.put("roles", roles);
        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(now) // 토큰 발행 일자
                .setExpiration(new Date(now.getTime() + tokenValidMilisecond)) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }

    //Jwt 토큰 생성 with User
    public String createToken(User user) {

        Claims claims = Jwts.claims().setSubject(user.getUid());

        claims.put("msrl", user.getMsrl());
        claims.put("password", user.getPassword());
        claims.put("roles", user.getRoles());
        claims.put("name", user.getName());

        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(now) // 토큰 발행 일자
                .setExpiration(new Date(now.getTime() + accessTokenValidMilisecond)) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }

    //Jwt 토큰 생성 with User and now
    public String createToken(User user, LocalDateTime now, LocalDateTime expiresAt) {

        Claims claims = Jwts.claims().setSubject(user.getUid());

        claims.put("msrl", user.getMsrl());
        claims.put("password", user.getPassword());
        claims.put("roles", user.getRoles());
        claims.put("name", user.getName());


        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant())) // 토큰 발행 일자
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant())) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }


    // Jwt 토큰 생성 with User return JwtResponseDto
    public JwtResponseDto save(User user) {

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime accessTokenExpiresAt = now.plusMinutes(30);
        final LocalDateTime refreshTokenExpiresAt = now.plusWeeks(2);

        // CREATE ACCESS_TOOKEN
        final String accessToken = createToken(user, now, accessTokenExpiresAt);

        // CREATE REFRESH_TOKEN
        final String refreshToken = createToken(user, now, refreshTokenExpiresAt);

        //  CREATE JwtResponseDto
        return JwtResponseDto.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // Jwt 토큰으로 인증 정보를 조회
    // DB 접근
//    public Authentication getAuthentication(String token) {
//        final UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
//        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
//    }
    //DB NO 접근
    public Authentication getAuthentication(String token) {

        final User user = getUserParseToken(token);

        //  =============== 로그 확인 =============
        log.info("============== JwtTokenProvider.getAuthentication ==============");
        log.info("user ::: " + user);
        log.info("==================================================================");

        assert user != null : "user must not be blank";

        return new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private User getUserParseToken(final String token) {

        final Claims claims = getClaimsFromToken(token);
        final String uid = claims.getSubject();
        final Long msrl = claims.get("msrl", Long.class);
        final String password = claims.get("password", String.class);
        final List<String> roles = claims.get("roles", List.class);
        final String name = claims.get("name", String.class);

        final User user = User.builder()
                .roles(roles)
                .msrl(msrl)
                .password(password)
                .name(name)
                .build();

        log.info("uid :::" + uid);
        log.info("user ::: " + user);

        return user;
    }


    // Jwt 토큰에서 회원 구별 정보 추출
    public String getUserPk(String token) {
        final Claims c = getClaimsFromToken(token);
        log.info("c.getSubject() :::" + c.getSubject());
        return c.getSubject();
    }


    // Request 의 Header 에서 token 파싱 : "X-AUTH-TOKEN: jwt 토큰"
    public String resolveToken(HttpServletRequest req) {
        return req.getHeader(ACCESS_TOKEN_KEY);
    }

    // Jwt 토큰의 유효성 + 만료 일자 확인
    public boolean validateToken(String token) {
        try {
            final Claims claims = getClaimsFromToken(token);

//            if (null != redisTemplate.opsForValue().get(Constant.REDIS_PREFIX + jwtToken)) {
//                log.info("이미 로그아웃 처리된 사용자");
//                return false;
//            }
            return !claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException eje) {
            //JWT 를 생성할 때 지정한 유효 기간 초과할 때.
            log.info("JWT 유효 기간 초과");
            throw new RuntimeException("JWT 유효기간 초과");
        } catch (UnsupportedJwtException uje) {
            // 예상 하는 형식과 일치 하지 않는 특정 형식이나 구성의 JWT일 때
            log.info("JWT 형식 불일치");
            throw new RuntimeException("JWT 형식 불일치");
        } catch (MalformedJwtException mje) {
            //JWT 가 올바 르게 구성 되지 않았을 때
            log.info("잘못된 JWT 구성");
            throw new RuntimeException("잘못된 JWT 구성");
        } catch (SignatureException se) {
            //JWT 의 기존 서명을 확인 하지 못했을 때
            log.info("JWT 서명 확인 불가");
            throw new RuntimeException("JWT 서명 확인 불가");
        } catch (IllegalArgumentException iae) {
            log.info("JWT IllegalArgumentException");
            throw new RuntimeException("JWT IllegalArgumentException");
        } catch (Exception e) {
            log.info("JWT 검증 중, 알 수 없는 오류 발생");
            throw new RuntimeException("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
        }

    }
}