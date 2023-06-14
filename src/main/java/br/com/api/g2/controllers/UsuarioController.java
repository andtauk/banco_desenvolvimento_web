package br.com.api.g2.controllers;

import java.io.IOException;
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
import br.com.api.g2.domain.Usuario;
import br.com.api.g2.dto.UsuarioDTO;
import br.com.api.g2.services.EmailService;
import br.com.api.g2.services.FotoService;
import br.com.api.g2.services.UsuarioService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;

@Valid
@RestController
@RequestMapping("/usuario")
@CrossOrigin(origins = "http://localhost:5173")
public class UsuarioController  {

	@Autowired
	UsuarioService usuarioService;

	@Autowired 
	EmailService emailService;
	
	@Autowired 
	FotoService fotoService;


	@GetMapping("/lista/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Encontra usuario por id - ADM e USER", description= "Encontrar usuario por id")
	public Usuario findId(@PathVariable("id") Integer id) {
		return usuarioService.buscarUsuarioId(id);
	}

	@GetMapping("/lista")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Lista todos os usuarios - ADM e USER", description= "Listagem de usuarios - ADMIN")
	public List<Usuario> findAllId() {
		return usuarioService.buscarUsuarios();
	}
	
	@Transactional
	@GetMapping("/{id}/foto")
	public ResponseEntity<byte[]> buscarFoto(@PathVariable Integer id){ 
		Foto foto = fotoService.buscarPorIdUsuario(id);
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-type", foto.getTipo());
		headers.add("Content-length", String.valueOf(foto.getDados().length));
		return new ResponseEntity<>(foto.getDados(), headers, HttpStatus.OK);
	}
	
	@Transactional
	@PostMapping(value = "/inserir",consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
	//@SecurityRequirement(name = "Bearer Auth")
	//@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Inserir usuarios no banco de dados - PERMIT ALL", description= "Inserção de usuarios no banco de dados - ADMIN")
	public UsuarioDTO cadastrarUsuario(@RequestParam String email, @RequestPart UsuarioDTO usuarioDTO,@RequestPart MultipartFile foto) throws MessagingException, IOException {
		emailService.envioEmailUsuarioCadastrado(email,usuarioDTO);
		return usuarioService.cadastrarUsuario(usuarioDTO,foto);
	}

	@PutMapping("/atualizar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Atualiza usuario por id - ADM e USER", description= "Atualiza usuario")
	public UsuarioDTO atualizarUsuario(@PathVariable("id") Integer id, @RequestBody UsuarioDTO usuarioSolicitado) {

		return usuarioService.atualizarUsuario(id, usuarioSolicitado);
	}

	@DeleteMapping("deletar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Deleta usuario - ADM e USER", description= "Deleta usuario")
	public void deletarUsuario(@PathVariable("id") Integer id) {
		usuarioService.deletarUsuario(id);
	}

}
