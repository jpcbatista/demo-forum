package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;
public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {

	private TokenService tokenService;

	public AutenticacaoViaTokenFilter(TokenService tokenService) {
		this.tokenService = tokenService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String token = tokenService.recuperarToken(request);
		boolean valido = tokenService.isTokenValido(token);

		if(valido) {
			tokenService.autenticarCliente(token);
		}
		
		filterChain.doFilter(request, response);

	}

}
