package com.eauction.gateway;

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

import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

	private static final Logger logger = LogManager.getLogger(AuthorizationHeaderFilter.class);

	@Value("${jwt.mac.key}")
	private String jwtMacKey;
	
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
		logger.info("onError err == {}", err);
		return response.setComplete();
	}

	private boolean isJwtValid(String jwt) {
		
		boolean returnValue = true;
		String subject = null;
		try {
			//subject = Jwts.parser().setSigningKey(tokenSecret).parseClaimsJws(jwt).getBody().getSubject();
			subject = Jwts.parserBuilder().setSigningKey(jwtMacKey.getBytes()).build().parseClaimsJws(jwt).getBody().getSubject();
		} catch (Exception ex) {
			returnValue = false;
		}

		if (subject == null || subject.isEmpty()) {
			returnValue = false;
		}
		
		logger.info("isJwtValid returnValue == {}", returnValue);

		return returnValue;
	}
}