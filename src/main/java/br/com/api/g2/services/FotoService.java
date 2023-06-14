
package br.com.api.g2.services;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import br.com.api.g2.domain.Foto;
import br.com.api.g2.domain.Produto;
import br.com.api.g2.domain.Usuario;
import br.com.api.g2.repositories.FotoRepository;


@Service
public class FotoService {

	@Autowired
	FotoRepository fotoRepository;

	@Autowired
	UsuarioService usuarioService;
	
	@Autowired
	ProdutoService produtoService;


	public Foto cadastrarFotoUsuario(MultipartFile foto, Usuario usuario) throws IOException {

		//Usuario usuarioFoto = new Usuario();
		//usuarioFoto = usuarioService.buscarUsuarioId(usuario.getUsuarioId());

		//if (usuario != null) {

		//	try {
				Foto fotoUsuario = new Foto();

				fotoUsuario.setDados(foto.getBytes());
				fotoUsuario.setTipo(foto.getContentType());
				fotoUsuario.setNome(foto.getOriginalFilename());
				fotoUsuario.setUsuario(usuario);
				return fotoRepository.save(fotoUsuario);

		//	} catch (IOException e) {
		//		e.printStackTrace();
		//	}

		//}
		//return null;
	}

	public Foto cadastrarFotoProduto(MultipartFile foto, Produto produto) {
		Produto produtoFoto =  new Produto();
		produtoFoto = produtoService.buscarProdutoId(produto.getProdutoId());
		
		if(produto != null) {
			try {
				Foto fotoProduto = new Foto();
				
				fotoProduto.setDados(foto.getBytes());
				fotoProduto.setTipo(foto.getContentType());
				fotoProduto.setNome(foto.getOriginalFilename());
				fotoProduto.setProduto(produto);
				fotoRepository.save(fotoProduto);
				return fotoProduto;
				
			}catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	public Foto buscarPorIdUsuario(Integer id) {
		Usuario usuario = new Usuario();
		usuario.setUsuarioId(id);
		Optional<Foto>foto = fotoRepository.findByUsuario(usuario);
		if(!foto.isPresent()) {
			return null;
		}
		return foto.get();
			
			
	}
	
	public Foto buscarPorIdProduto(Integer id) {
		Produto produto = new Produto();
		produto.setProdutoId(id);;
		Optional<Foto>foto = fotoRepository.findByProduto(produto);
		if(!foto.isPresent()) {
			return null;
		}
		return foto.get();
			
			
	}
	
	public List<Foto> fotos () {
		return fotoRepository.findAll();
	}
}
