package com.debuggeandoideas.gateway.filters;

import com.debuggeandoideas.gateway.dtos.TokenDto;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GatewayFilter {
    private final WebClient webClient;

    private static final String AUTH_VALIDATE_URI = "http://ms-auth:3030/auth-server/auth/jwt";
    private static final String ACCESS_TOKEN_HEADER_NAME = "accessToken";

    public AuthFilter(){
        this.webClient = WebClient.builder().build();
    }

    /**
     * Validates token in request, if everything ok, it will send petition another microservice
     * and pass to the next GatewayFilterChain
     * @param exchange the current server exchange
     * @param chain provides a way to delegate to the next filter
     * @return
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if(!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
            return this.onError(exchange);
        }
        final var tokenHeader = exchange.
                getRequest()
                .getHeaders()
                .get(HttpHeaders.AUTHORIZATION).get(0);
        final var chunk = tokenHeader.split(" ");
        if(chunk.length != 2 || !chunk[0].equals("Bearer")){
            return this.onError(exchange);
        }
        final var token = chunk[1];

        System.out.println("Valid token");

        return this.webClient.
                post()
                .uri(AUTH_VALIDATE_URI)
                .header(ACCESS_TOKEN_HEADER_NAME, token)
                .retrieve()
                .bodyToMono(TokenDto.class)
                .map(response -> exchange)
                .flatMap(chain::filter);
    }

    /**
     * It returns bad request status
     * @param exchange
     * @return Mono<Void>
     */
    private Mono<Void> onError(ServerWebExchange exchange){
        final var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        return response.setComplete();
    }
}