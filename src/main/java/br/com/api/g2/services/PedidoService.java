package br.com.api.g2.services;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.api.g2.domain.Pedido;
import br.com.api.g2.repositories.PedidoRepository;

@Service
public class PedidoService {
	
	@Autowired
	PedidoRepository pedidoRepository;


	public Optional<Pedido> buscarPedidoId(Integer id) {
		return pedidoRepository.findById(id);
	}

	public List<Pedido> buscarPedidos() {
		return pedidoRepository.findAll();
	}

	public Pedido cadastrarPedido(Pedido pedido) {
		pedido.setData(LocalDateTime.now());
		return pedidoRepository.save(pedido);
	}

	public Pedido atualizarPedido(Integer id, Pedido pedidoSolicitado) {
		Optional<Pedido> pedidoExistenteOptional = pedidoRepository.findById(id);
		if (pedidoExistenteOptional.isPresent()) {
			Pedido pedidoExistente = pedidoExistenteOptional.get();
			pedidoExistente.setData(pedidoSolicitado.getData());
			
			return pedidoRepository.save(pedidoExistente);
		} else {
			throw new IllegalArgumentException("Pedido não encontrado");
		}
	}

	public void deletarPedido(Integer id) {
		Optional<Pedido> pedidoExistenteOptional = pedidoRepository.findById(id);
		if (pedidoExistenteOptional.isPresent()) {
			Pedido pedidoExistente = pedidoExistenteOptional.get();
			pedidoRepository.delete(pedidoExistente);
		} else {
			throw new IllegalArgumentException("Pedido não existente");
		}
	}
}

	
	//Colocar esse código dentro do metodo que precisa salvar a info com data e hora
//	String strLocalDateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//	LocalDateTime data = LocalDateTime.parse(strLocalDateTime, DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//	"pedido".setData(LocalDateTime.now());

