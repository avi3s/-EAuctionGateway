package com.eauction.gateway;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

	private static final Logger LOGGER = LogManager.getLogger(AuthorizationHeaderFilter.class);

	@Value("${publicKey}")
	private String publicKey;
	
	@Value("${authorization.missing}")
	private String authorizationMissing;
	
	@Value("${token.invalid}")
	private String tokenInvalid;

	public AuthorizationHeaderFilter() {
		super(Config.class);
	}

	public static class Config {
		// Put configuration properties here
	}

	@Override
	public GatewayFilter apply(Config config) {
		
		return (exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();
			if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, authorizationMissing, HttpStatus.UNAUTHORIZED);
			}
			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer", "");
			if (!isJwtValid(jwt)) {
				return onError(exchange, tokenInvalid, HttpStatus.UNAUTHORIZED);
			}
			return chain.filter(exchange);
		};
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		LOGGER.info("onError err == {}", err);
		return response.setComplete();
	}
	
	private Jws<Claims> parseJwt(String jwtString) throws InvalidKeySpecException, NoSuchAlgorithmException {

		LOGGER.info("parseJwt Start ==>> {}"+ jwtString);
	    PublicKey publicKey = getPublicKey();

	    Jws<Claims> jwt = Jwts.parserBuilder()
	            			  .setSigningKey(publicKey)
	            			  .build()
	            			  .parseClaimsJws(jwtString);
	    LOGGER.info("parseJwt End ==>> {}", jwt);
	    return jwt;
	}

	private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		
	    String rsaPublicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
	    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    PublicKey publicKey = kf.generatePublic(keySpec);
	    return publicKey;
	}
	
	private boolean isJwtValid(String jwt) {
		
		boolean returnValue = true;
		try {
			returnValue = parseJwt(jwt).getBody().getId().contains("-");
		} catch (Exception e) {
			System.err.println(ExceptionUtils.getStackTrace(e));
			returnValue = false;
		}

		LOGGER.info("isJwtValid returnValue == {}", returnValue);

		return returnValue;
	}
}