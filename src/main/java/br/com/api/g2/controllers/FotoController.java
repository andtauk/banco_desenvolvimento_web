package br.com.api.g2.controllers;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import br.com.api.g2.domain.Foto;
import br.com.api.g2.domain.Produto;
import br.com.api.g2.domain.Usuario;
import br.com.api.g2.services.FotoService;
import br.com.api.g2.services.UsuarioService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;

@RestController
@RequestMapping("/foto")
public class FotoController {

	@Autowired
	FotoService fotoService;

	@Autowired
	UsuarioService usuarioService;

	@PostMapping("/foto-usuario")
	@Operation(summary = "Inserir foto no banco de dados - ADM e USER", description = "Inserção de foto banco de dados - ")
	public Foto cadastrarFotoUsuario(@RequestBody Usuario usuario, @RequestParam MultipartFile foto)
			throws MessagingException, IOException {
		return fotoService.cadastrarFotoUsuario(foto, usuario);
	}
	
	
	@PostMapping("/foto-produto")
	@Operation(summary = "Inserir foto produto no banco de dados - ADM e USER", description = "Inserção de foto produto banco de dados - ")
	public Foto cadastrarFotoProduto(@RequestBody Produto produto, @RequestParam MultipartFile foto)
			throws MessagingException {
		return fotoService.cadastrarFotoProduto(foto, produto);
	}
}
