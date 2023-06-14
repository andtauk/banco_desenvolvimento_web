package br.com.api.g2.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.api.g2.domain.Foto;
import br.com.api.g2.domain.Produto;
import br.com.api.g2.domain.Usuario;

@Repository("foto")
public interface FotoRepository extends JpaRepository<Foto, Integer> {

	public Optional<Foto> findByUsuario(Usuario usuario);

	public Optional<Foto> findByProduto(Produto produto);

}
