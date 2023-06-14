package br.com.api.g2.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.api.g2.domain.Pedido;

public interface PedidoRepository extends JpaRepository<Pedido, Integer> {

	Optional<Pedido> findById(Integer id);

}
