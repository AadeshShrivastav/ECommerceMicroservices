package com.apigateway.apigateway.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        if(!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            return chain.filter(exchange);
        }
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if(authHeader != null && authHeader.startsWith("Bearer")) {
            String token = authHeader.substring(7);

        if (!jwtTokenProvider.validateToken(token)) {
            throw new RuntimeException("Invalid JWT Token");
        }

        String username = jwtTokenProvider.getUsernameFromJWT(token);

        // Add the username as a header to pass to downstream microservices
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("username", username)
                .build();

        exchange = exchange.mutate().request(modifiedRequest).build();
    }

        return chain.filter(exchange);
    }


    @Override
    public int getOrder() {
        return -1;
    }
}
