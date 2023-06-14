package br.com.api.g2.services;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.com.api.g2.domain.Categoria;
import br.com.api.g2.domain.Foto;
import br.com.api.g2.domain.Produto;
import br.com.api.g2.repositories.CategoriaRepository;
import br.com.api.g2.repositories.FotoRepository;
import br.com.api.g2.repositories.ProdutoRepository;

@Service
public class ProdutoService {

	@Autowired
	ProdutoRepository produtoRepository;

	@Autowired
	FotoService fotoService;

	@Autowired
	CategoriaRepository categoriaRepository;

	@Autowired
	FotoRepository fotoRepository;

	public Produto buscarProdutoId(Integer id) {
		Produto produto = new Produto();
		produto = produtoRepository.findById(id).orElse(null);
		return produto;

	}

	public List<Produto> buscarProdutos() {
		return produtoRepository.findAll();
	}

	public Produto cadastrarProduto(Produto produto, MultipartFile foto) {

		

		Categoria categoria = new Categoria();
		categoria = produto.getCategoria();
		categoriaRepository.save(categoria);

		
		Produto produtoSalvo = produtoRepository.save(produto);
		produto.setUrl(adicionarImagemUri(produtoSalvo));
		atualizarProduto(produto.getProdutoId(), produto);
		 
		fotoService.cadastrarFotoProduto(foto, produto);
		return produto;
	}

	private String adicionarImagemUri(Produto produto) {
		URI uri = ServletUriComponentsBuilder.fromCurrentContextPath().path("/produto/" + produto.getProdutoId() + "/foto")
				.buildAndExpand(produto.getProdutoId()).toUri();
		produto.setUrl(uri.toString());
		return produto.getUrl();
	}

	public Produto atualizarProduto(Integer id, Produto produtoSolicitado) {
		Optional<Produto> produtoExistenteOptional = produtoRepository.findById(id);
		if (produtoExistenteOptional.isPresent()) {
			Produto produtoExistente = produtoExistenteOptional.get();
			produtoExistente.setNome(produtoSolicitado.getNome());
			produtoExistente.setDescricao(produtoSolicitado.getDescricao());
			produtoExistente.setQuantidadeEstoque(produtoSolicitado.getQuantidadeEstoque());
			produtoExistente.setData(produtoSolicitado.getData());
			produtoExistente.setValorUnitario(produtoSolicitado.getValorUnitario());

			return produtoRepository.save(produtoExistente);
		} else {
			throw new IllegalArgumentException("Produto não encontrado");
		}
	}

	public void deletarProduto(Integer id) {
		Optional<Produto> produtoExistenteOptional = produtoRepository.findById(id);
		System.out.println("1");
		if (produtoExistenteOptional.isPresent()) {
			System.out.println("2");
			List<Foto> fotos = fotoService.fotos();
			for (Foto foto : fotos) {
				System.out.println("varredura");
				if (foto.getProduto() != null) {
					System.out.println("3");
					if (produtoExistenteOptional.get().getProdutoId() == foto.getProduto().getProdutoId()) {
						System.out.println("4");
						fotoRepository.deleteById(foto.getFotoId());
						Produto produtoExistente = produtoExistenteOptional.get();
						System.out.println("id: " + produtoExistente.getProdutoId());
						produtoRepository.deleteById(produtoExistente.getProdutoId());
					}

				}
			}
		}	else {
			System.out.println("5");
			throw new IllegalArgumentException("Produto não existente");
		}
	}

}
// Colocar esse código dentro do metodo que precisa salvar a info com data e
// hora
//	String strLocalDateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//	LocalDateTime data = LocalDateTime.parse(strLocalDateTime, DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//	"produto".setData(LocalDateTime.now());
