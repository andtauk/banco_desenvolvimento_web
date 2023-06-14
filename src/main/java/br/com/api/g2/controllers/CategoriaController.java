package br.com.api.g2.controllers;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
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

import br.com.api.g2.domain.Categoria;
import br.com.api.g2.services.CategoriaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;

@Valid
@RestController
@RequestMapping("/categoria")
@CrossOrigin(origins = "http://localhost:5173")
public class CategoriaController {

	@Autowired
	CategoriaService categoriaService;

	@GetMapping("/lista/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary = "Encontra categoria por id ADM", description = "Encontrar categoria por id")
	public Optional<Categoria> findId(@PathVariable("id") Integer id) {
		return categoriaService.buscarCategoriaId(id);
	}

	@GetMapping("/lista")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary = "Lista todos as categorias - ADM", description = "Listagem de categorias")
	public List<Categoria> findAllId(Pageable page) {
		return categoriaService.buscarCategorias(page);
	}

//	@GetMapping("/spam")//pra view do banco de dados
//	public List<Categoria> spam(){
//		return categoriaService.spam();
	// }

	@PostMapping("/inserir")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary = "Inserir categoria no banco de dados - ADM", description = "Listagem as categoria sno banco de dados")
	public Categoria cadastrarCategoria(@RequestParam String email, @RequestBody Categoria categoria)
			throws MessagingException {
		return categoriaService.cadastrarCategoria(categoria);
	}

	@PutMapping("/atualizar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary = "Atualiza categoria por id - ADM", description = "Atualiza categorias")
	public Categoria atualizarCategoria(@PathVariable("id") Integer id, @RequestBody Categoria categoriaSolicitada) {
		return categoriaService.atualizarCategoria(id, categoriaSolicitada);
	}

	@DeleteMapping("/deletar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@Operation(summary = "Deleta categorias - ADM", description = "Deleta categorias")
	public void deletarCategoria(@PathVariable("id") Integer id) {
		categoriaService.deletarCategoria(id);
	}

}
