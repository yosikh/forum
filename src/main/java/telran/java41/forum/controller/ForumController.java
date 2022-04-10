package telran.java41.forum.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import telran.java41.forum.dto.DatePeriodDto;
import telran.java41.forum.dto.NewCommentDto;
import telran.java41.forum.dto.NewPostDto;
import telran.java41.forum.dto.PostDto;
import telran.java41.forum.service.ForumService;

@RestController
@RequestMapping("/forum")
public class ForumController {
	
	ForumService forumService;
	
	@Autowired
	public ForumController(ForumService forumService) {
		this.forumService = forumService;
	}

	@PostMapping("/post/{author}")
	public PostDto addPost(@PathVariable String author, @RequestBody NewPostDto newPostDto) {
		return forumService.addNewPost(newPostDto, author);
	}
	
	@GetMapping("/post/{id}")
	public PostDto findPostById(@PathVariable String id) {
		return forumService.getPost(id);
	}

	@PutMapping("/post/{id}/like")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void addLike(@PathVariable String id) {
		forumService.addLike(id);
	}

	@PutMapping("/post/{id}/comment/{user}")
	public PostDto addComment(@PathVariable String id, @PathVariable String user, @RequestBody NewCommentDto newCommentDto) {
		return forumService.addComment(id, user, newCommentDto);
	}

	@DeleteMapping("/post/{id}")
	public PostDto deletePost(@PathVariable String id) {
		return forumService.removePost(id);
	}

	@PutMapping("/post/{id}")
	public PostDto updatePost(@PathVariable String id, @RequestBody NewPostDto postUpdateDto) {
		return forumService.updatePost(postUpdateDto, id);
	}

	@GetMapping("/posts/author/{author}")
	public Iterable<PostDto> findPostsByAuthor(@PathVariable String author) {
		return forumService.findPostsByAuthor(author);
	}
	
	@PostMapping("/posts/tags")
	public Iterable<PostDto> findPostsByTags(@RequestBody List<String> tags) {
		return forumService.findPostsByTags(tags);
	}

	@PostMapping("/posts/period")
	public Iterable<PostDto> findPostsByPeriod(@RequestBody DatePeriodDto datePeriodDto) {
		return forumService.findPostsByDates(datePeriodDto);
	}
	
}
