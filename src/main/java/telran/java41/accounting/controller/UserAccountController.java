package telran.java41.accounting.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import telran.java41.accounting.dto.RolesResponseDto;
import telran.java41.accounting.dto.UserAccountResponseDto;
import telran.java41.accounting.dto.UserRegisterDto;
import telran.java41.accounting.dto.UserUpdateDto;
import telran.java41.accounting.service.UserAccountService;

@RestController
@RequestMapping("/account")
public class UserAccountController {
	
	UserAccountService accountService;

	@Autowired
	public UserAccountController(UserAccountService accountService) {
		this.accountService = accountService;
	}
	
	@PostMapping("/register")
	public UserAccountResponseDto register(@RequestBody UserRegisterDto registerDto) {
		return accountService.addUser(registerDto);
	}
	
//	@PostMapping("/login")
//	public UserAccountResponseDto login(@RequestHeader("Authorization") String token) {
//		String login = getLoginFromToken(token);
//		return accountService.getUser(login);
//	}
	@PostMapping("/login")
	public UserAccountResponseDto login(Principal principal) {
		return accountService.getUser(principal.getName());
	}
	
	@DeleteMapping("/user/{login}")
	public UserAccountResponseDto removeUser(@PathVariable String login) {
		return accountService.removeUser(login);
	}
	
	@PutMapping("/user/{login}")
	public UserAccountResponseDto updateUser(@PathVariable String login, @RequestBody UserUpdateDto updateDto) {
		return accountService.editUser(login, updateDto);
	}
	
	@PutMapping("/user/{login}/role/{role}")
	public RolesResponseDto addRole(@PathVariable String login, @PathVariable String role) {
		return accountService.changeRolesList(login, role, true);
	}
	
	@DeleteMapping("/user/{login}/role/{role}")
	public RolesResponseDto removeRole(@PathVariable String login, @PathVariable String role) {
		return accountService.changeRolesList(login, role, false);
	}
	
	@PutMapping("/password")
	public void changePassword(Principal principal, @RequestHeader("X-Password") String newPassword) {
		accountService.changePassword(principal.getName(), newPassword);
	}
	
}
