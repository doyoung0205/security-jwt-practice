package com.codej99.doyoung.rest.apipractice.config.security.jwt;

import lombok.extern.java.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Log
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    // Jwt Provier 주입
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // Request로 들어오는 Jwt Token의 유효성을 검증(jwtTokenProvider.validateToken)하는 filter를 filterChain에 등록합니다.
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
        log.info("[JwtAuthenticationFilter.doFilter] token  ::: " + token);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            final Authentication authentication = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}


//try{
//        claims = Jwts.parser()
//        .setSigningKey(secret.getBytes("UTF-8"))
//        .parseClaimsJws(token).getBody();
//        // OK, we can trust this JWT
//
//        }catch(ExpiredJwtException eje){
////JWT를 생성할 때 지정한 유효기간 초과할 때.
//        LOGGER.debug("JWT 유효기간 초과");
//        throw new RuntimeException("JWT 유효기간 초과");
//        }catch(UnsupportedJwtException uje){
////예상하는 형식과 일치하지 않는 특정 형식이나 구성의 JWT일 때
//        LOGGER.debug("JWT 형식 불일치");
//        throw new RuntimeException("JWT 형식 불일치");
//        }catch(MalformedJwtException mje){
////JWT가 올바르게 구성되지 않았을 때
//        LOGGER.debug("잘못된 JWT 구성");
//        throw new RuntimeException("잘못된 JWT 구성");
//        }catch(SignatureException se){
////JWT의 기존 서명을 확인하지 못했을 때
//        LOGGER.debug("JWT 서명 확인 불가");
//        throw new RuntimeException("JWT 서명 확인 불가");
//        }catch(IllegalArgumentException iae){
//        LOGGER.debug("JWT IllegalArgumentException");
//        throw new RuntimeException("JWT IllegalArgumentException");
//        }catch (Exception e) {
//        LOGGER.debug("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
//        throw new RuntimeException("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
//        }