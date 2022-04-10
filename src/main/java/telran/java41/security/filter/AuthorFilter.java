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
import telran.java41.forum.dao.PostRepository;
import telran.java41.forum.model.Post;

@Service
@Order(13)
public class AuthorFilter implements Filter {

	UserAccountRepository accountRepository;
	PostRepository postRepository;
	String login;
	
	@Autowired
	public AuthorFilter(UserAccountRepository accountRepository, PostRepository postRepository) {
		this.accountRepository = accountRepository;
		this.postRepository = postRepository;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			UserAccount userAccount = accountRepository.findById(request.getUserPrincipal().getName()).get();
			String author = userAccount.getLogin();
			if (!author.equals(login)) {
				response.sendError(403, "Author: author " + author + " is not allowed to do this");
				return;
			}
		}
		
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		if ("POST".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/?")) {
			login = path.split("/")[3];
			return true;
		}
		if ("PUT".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/comment/\\w+/?")) {
			String id = path.split("/")[3];
			Post post = postRepository.findById(id).orElse(null);
			if (post == null) {
				return false;
			}
			login = post.getAuthor();
			return true;
		}
		return false;
	}

}
