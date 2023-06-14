package br.com.api.g2.controllers;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.web.bind.annotation.RestController;

import br.com.api.g2.domain.Endereco;
import br.com.api.g2.services.EnderecoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;

@Valid
@RestController
@RequestMapping("/endereco")
@CrossOrigin(origins = "http://localhost:5173")
public class EnderecoController {

	@Autowired
	EnderecoService enderecoService;


	@GetMapping("/lista/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary= "Encontra endereço por id - ADM", description= "Encontrar endereço por id")
	public Optional<Endereco> findId(@PathVariable("id") Integer id) {
		return enderecoService.buscarEnderecoId(id);
	}

	@GetMapping("/lista")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary= "Lista todos os endereço - ADM", description= "Listagem de endereços")
	public List<Endereco> findAllId() {
		return enderecoService.buscarEnderecos();
	}

	@PostMapping("/inserir")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary= "Inserir endereço no banco de dados - ADM", description= "Inserção de endereço no banco de dados")
	public Endereco cadastrarEndereco(@RequestParam String email, @RequestBody Endereco endereco) throws MessagingException {
		return enderecoService.cadastrarEndereco(endereco);
	}
		

	@PutMapping("/atualizar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary= "Atualiza endereço por id - ADM", description= "Atualiza endereço")
	public Endereco atualizarEndereco(@PathVariable("id") Integer id, @RequestBody Endereco enderecoSolicitado) {
		return enderecoService.atualizarEndereco(id, enderecoSolicitado);
	}

	@DeleteMapping("/deletar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary= "Deleta endereço - ADM", description= "Deleta endereço")
	public void deletarEndereco(@PathVariable("id") Integer id) {
		enderecoService.deletarEndereco(id);
	}
}
