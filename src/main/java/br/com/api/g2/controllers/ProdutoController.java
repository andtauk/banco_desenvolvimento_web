package br.com.api.g2.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import br.com.api.g2.domain.Foto;
import br.com.api.g2.domain.Produto;
import br.com.api.g2.services.EmailService;
import br.com.api.g2.services.FotoService;
import br.com.api.g2.services.ProdutoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;

@Valid
@RestController
@RequestMapping("/produto")
@CrossOrigin(origins = "http://localhost:5173")
public class ProdutoController  {

	@Autowired
	ProdutoService produtoService;

	@Autowired 
	EmailService emailService;
	
	@Autowired
	FotoService fotoService;


	@GetMapping("lista/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Encontra produto por id - ADM e USER", description= "Encontrar produto por id")
	public Produto findId(@PathVariable("id") Integer id) {
		return produtoService.buscarProdutoId(id);
	}

	@GetMapping("/lista")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Lista todos os produtos - ADM e USER", description= "Listagem de produtos")
	public List<Produto> findAllId() {
		return produtoService.buscarProdutos();
	}
	
	@Transactional
	@GetMapping("/{id}/foto")
	public ResponseEntity<byte[]> buscarFoto(@PathVariable Integer id){ 
		Foto foto = fotoService.buscarPorIdProduto(id);
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-type", foto.getTipo());
		headers.add("Content-length", String.valueOf(foto.getDados().length));
		return new ResponseEntity<>(foto.getDados(), headers, HttpStatus.OK);
	}

	
	@PostMapping(value = "/inserir", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Inserir produtos no banco de dados - ADM e USER", description= "Inserção de produtos no banco de dados")
	public Produto cadastrarProduto(@RequestParam String email, @RequestPart Produto produto, @RequestPart MultipartFile foto) throws MessagingException {
		emailService.envioEmailProdutoCadastrado(email, produto);
		return produtoService.cadastrarProduto(produto, foto);
	}
		

	@PutMapping("/atualizar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Atualiza produto por id - ADM e USER", description= "Atualiza produto")
	public Produto atualizarProduto(@PathVariable("id") Integer id, @RequestBody Produto produtoSolicitado) {
		return produtoService.atualizarProduto(id, produtoSolicitado);
	}

	@DeleteMapping("/deletar/{id}")
	//@SecurityRequirement(name = "Bearer Auth")
	//@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Deleta produto - ADM e USER", description= "Deleta produto")
	public void deletarProduto(@PathVariable("id") Integer id) {
		
		produtoService.deletarProduto(id);
	}
}
