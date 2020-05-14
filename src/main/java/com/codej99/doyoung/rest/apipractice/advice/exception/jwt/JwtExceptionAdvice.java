package com.codej99.doyoung.rest.apipractice.advice.exception.jwt;

import com.codej99.doyoung.rest.apipractice.model.response.CommonResult;
import com.codej99.doyoung.rest.apipractice.service.ResponseService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
@RestControllerAdvice
@Log
public class JwtExceptionAdvice {

    private final ResponseService responseService;

    private final MessageSource messageSource;

    //JWT 유효 기간 초과
    @ExceptionHandler(ExpiredJwtException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    protected CommonResult expiredJwtException(HttpServletRequest request, Exception e) {
        log.info("JWT 유효 기간 초과");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.expired.code")), getMessage("jwt.expired.msg"));
    }

    //Access Token JWT 유효 기간 초과
    @ExceptionHandler(AccessTokenExpiredJwtException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult accessTokenExpiredJwtException(HttpServletRequest request, Exception e) {
        log.info("Access Token JWT 유효 기간 초과");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.acessTokenExpired.code")), getMessage("jwt.acessTokenExpired.msg"));
    }

    //Refresh Token JWT 유효 기간 초과
    @ExceptionHandler(RefreshTokenExpiredJwtException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult refreshTokenExpiredJwtException(HttpServletRequest request, Exception e) {
        log.info("Refresh Token JWT 유효 기간 초과");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.refreshTokenExpired.code")), getMessage("jwt.refreshTokenExpired.msg"));
    }

    //JWT 형식 불일치
    @ExceptionHandler(UnsupportedJwtException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult unsupportedJwtException(HttpServletRequest request, Exception e) {
        log.info("JWT 형식 불일치");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.unsupported.code")), getMessage("jwt.unsupported.msg"));
    }

    //잘못된 JWT 구성
    @ExceptionHandler(MalformedJwtException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult malformedJwtException(HttpServletRequest request, Exception e) {
        log.info("잘못된 JWT 구성");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.malformed.code")), getMessage("jwt.malformed.msg"));
    }

    //JWT 서명 확인 불가
    @ExceptionHandler(SignatureException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult signatureException(HttpServletRequest request, Exception e) {
        log.info("JWT 서명 확인 불가");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.signature.code")), getMessage("jwt.signature.msg"));
    }

    //JWT IllegalArgumentException
    @ExceptionHandler(JwtIllegalArgumentException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult jwtIllegalArgumentException(HttpServletRequest request, Exception e) {
        log.info("JWT IllegalArgumentException");
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.illegalArgument.code")), getMessage("jwt.illegalArgument.msg"));
    }

    //JWT 검증 중, 알 수 없는 오류 발생
    @ExceptionHandler(JwtRuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected CommonResult jwtRuntimeException(HttpServletRequest request, Exception e) {
        log.info("JWT 검증 중, 알 수 없는 오류 발생" + e.getMessage());
        return responseService.getFailResult(Integer.parseInt(getMessage("jwt.jwtRuntime.code")), getMessage("jwt.jwtRuntime.msg"));
    }

    // code 정보에 해당하는 메시지를 조회합니다.
    private String getMessage(String code) {
        return getMessage(code, null);
    }

    // code 정보, 추가 argument 로 현재 locale 에 맞는 메시지를 조회합니다.
    private String getMessage(String code, Object[] args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }
}
