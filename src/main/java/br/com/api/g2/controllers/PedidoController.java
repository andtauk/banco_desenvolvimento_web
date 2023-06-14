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

import br.com.api.g2.domain.Pedido;
import br.com.api.g2.services.EmailService;
import br.com.api.g2.services.PedidoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;

@Valid
@RestController
@RequestMapping("/pedido")
@CrossOrigin(origins = "http://localhost:5173")
public class PedidoController  {

	@Autowired
	PedidoService pedidoService;

	@Autowired 
	EmailService emailService;


	@GetMapping("/lista/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Encontra pedido por id - ADM e USER", description= "Encontrar pedido por id")
	public Optional<Pedido> findId(@PathVariable("id") Integer id) {
		return pedidoService.buscarPedidoId(id);
	}

	@GetMapping("/lista")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Lista todos os pedidos - ADM e USER", description= "Listagem de pedidos")
	public List<Pedido> findAllId() {
		return pedidoService.buscarPedidos();
	}

	@PostMapping("/inserir")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Inserir pedido no banco de dados - ADM e USER", description= "Inserção de pedido no banco de dados")
	public Pedido cadastrarPedido(@RequestBody Pedido pedido) throws MessagingException {
		return pedidoService.cadastrarPedido(pedido);
	}
		

	@PutMapping("/atualizar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Atualiza pedido por id - ADM e USER", description= "Atualiza pedido")
	public Pedido atualizarPedido(@PathVariable("id") Integer id, @RequestBody Pedido pedidoSolicitado) {
		return pedidoService.atualizarPedido(id, pedidoSolicitado);
	}

	@DeleteMapping("/deletar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Deleta pedido - ADM e USER", description= "Deleta pedido")
	public void deletarPedido(@PathVariable("id") Integer id) {
		pedidoService.deletarPedido(id);
	}

}
