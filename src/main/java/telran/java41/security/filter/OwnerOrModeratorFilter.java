package telran.java41.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;

@Service
@Order(25)
public class OwnerOrModeratorFilter implements Filter {

	UserAccountRepository accountRepository;
	
	@Autowired
	public OwnerOrModeratorFilter(UserAccountRepository accountRepository) {
		this.accountRepository = accountRepository;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String login = request.getServletPath().split("/")[3];
			UserAccount userAccount = accountRepository.findById(request.getUserPrincipal().getName()).get();
			if (!(userAccount.getLogin().equals(login) || 
				  userAccount.getRoles().contains("Moderator".toUpperCase()))) {
				response.sendError(403, "OwnerOrAdmin: user " + userAccount.getLogin() + " is not allowed to do this");
				return;
			}
		}
		
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		return "DELETE".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/?");
	}

}
