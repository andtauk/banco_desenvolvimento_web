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

import br.com.api.g2.domain.ItemPedido;
import br.com.api.g2.services.ItemPedidoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;

@Valid
@RestController
@RequestMapping("/itemPedido")
@CrossOrigin(origins = "http://localhost:5173")
public class ItemPedidoController  {

	@Autowired
	ItemPedidoService itemPedidoService;


	@GetMapping("lista/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Encontra item pedido por id - ADM e USER", description= "Encontrar item pedido por id")
	public Optional<ItemPedido> findId(@PathVariable("id") Integer id) {
		return itemPedidoService.buscarItemPedidoId(id);
	}

	@GetMapping("/lista")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Lista todos os itens pedido -  ADM e USER", description= "Listagem de itens pedido")
	public List<ItemPedido> findAllId() {
		return itemPedidoService.buscarItensPedido();
	}

	@PostMapping("/inserir")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Inserir item pedido no banco de dados -  ADM e USER", description= "Inserção de item pedido no banco de dados")
	public ItemPedido cadastrarItemPedido(@RequestBody ItemPedido itemPedido) throws MessagingException {
		return itemPedidoService.cadastrarItemPedido(itemPedido);
	}
		

	@PutMapping("/atualizar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Atualiza item pedido por id -  ADM e USER", description= "Atualiza item pedido")
	public ItemPedido atualizarItemPedido(@PathVariable("id") Integer id, @RequestBody ItemPedido itemPedidoSolicitado) {
		return itemPedidoService.atualizarItemPedido(id, itemPedidoSolicitado);
	}

	@DeleteMapping("/deletar/{id}")
//	@SecurityRequirement(name = "Bearer Auth")
//	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	@Operation(summary= "Deleta item pedido -  ADM e USER", description= "Deleta item pedido")
	public void deletarItemPedido(@PathVariable("id") Integer id) {
		itemPedidoService.deletarItemPedido(id);
	}
}
