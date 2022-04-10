package telran.java41.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;

@Service
@Order(10)
public class AuthenticationFilter implements Filter {

	UserAccountRepository repository;
	
	@Autowired
	public AuthenticationFilter(UserAccountRepository repository) {
		this.repository = repository;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
				
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String token = request.getHeader("Authorization");
			String[] credentials;
			try {
				credentials = getCredentialsFromToken(token);
			} catch (Exception e) {
				response.sendError(401, "Token not valid");
				return;
			}
			UserAccount userAccount = repository.findById(credentials[0]).orElse(null);
			if (userAccount == null || !BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
				response.sendError(401, "User or password not valid");
				return;
			}
			//TODO Add Principal to request
			request = new WrappedRequest(request, userAccount.getLogin());
		}
		
		chain.doFilter(request, response);
	}
	
	private boolean checkEndPoint(String method, String path) {
		return !(("POST".equalsIgnoreCase(method) && path.matches("/account/register/?")) ||
				 ("GET".equalsIgnoreCase(method) && path.matches("/forum/posts/author/\\w+/?")) ||
				 ("POST".equalsIgnoreCase(method) && (path.matches("/forum/posts/tags/?") || 
						 							  path.matches("/forum/posts/period/?"))));
	}

	private String[] getCredentialsFromToken(String token) {
		token = token.split(" ")[1];
		String decode = new String(Base64.getDecoder().decode(token));
		String[] credentials = decode.split(":");
		return credentials;
	}

	private class WrappedRequest extends HttpServletRequestWrapper {
		String login;

		public WrappedRequest(HttpServletRequest request, String login) {
			super(request);
			this.login = login;
		}
		
		@Override
		public Principal getUserPrincipal() {
			return () -> login;
		}
		
	}
	
}
