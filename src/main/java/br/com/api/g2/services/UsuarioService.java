package br.com.api.g2.services;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.com.api.g2.domain.Endereco;
import br.com.api.g2.domain.Usuario;
import br.com.api.g2.dto.UsuarioDTO;
import br.com.api.g2.repositories.EnderecoRepository;
import br.com.api.g2.repositories.UsuarioRepository;
import br.com.api.g2.security.domain.Role;
import br.com.api.g2.security.domain.User;
import br.com.api.g2.security.enums.RoleEnum;
import br.com.api.g2.security.repositories.RoleRepository;
import br.com.api.g2.security.repositories.UserRepository;

@Service
public class UsuarioService {

	@Autowired
	UsuarioRepository usuarioRepository;

	@Autowired
	EnderecoRepository enderecoRepository;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	RoleRepository roleRepository;
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	FotoService fotoService;


	public Usuario buscarUsuarioId(Integer id) {
		Usuario usuario = new Usuario();
		usuario = usuarioRepository.findById(id).orElse(null);
		return usuario;
		
	}

	public List<Usuario> buscarUsuarios() {
		return usuarioRepository.findAll();
	}

	public UsuarioDTO cadastrarUsuario(UsuarioDTO usuarioDTO, MultipartFile foto) throws IOException {

		RestTemplate restTemplate = new RestTemplate();
		String uri = "http://viacep.com.br/ws/{cep}/json";
		Map<String, String> params = new HashMap<>();
		params.put("cep", usuarioDTO.getCep());
		Endereco endCadastro = restTemplate.getForObject(uri, Endereco.class, params);

		Endereco endereco = new Endereco();
		endereco.setCep(usuarioDTO.getCep());
		endereco.setLogradouro(endCadastro.getLogradouro());
		endereco.setComplemento(usuarioDTO.getComplemento());
		endereco.setBairro(endCadastro.getBairro());
		endereco.setLocalidade(endCadastro.getLocalidade());
		endereco.setUf(endCadastro.getUf());
		endereco.setNumero(usuarioDTO.getNumero());

		enderecoRepository.save(endereco);

		Usuario usuario = new Usuario();

		usuario.setNome(usuarioDTO.getNome());
		//usuario.setNomeUser(usuarioDTO.getNomeUser());
		usuario.setTelefone(usuarioDTO.getTelefone());
		//usuario.setEmail(usuarioDTO.getEmail());
		usuario.setCpf(usuarioDTO.getCpf());
		usuario.setCompra(usuarioDTO.isCompra());
		usuario.setVenda(usuarioDTO.isVenda());
		usuario.setData(usuarioDTO.getData());
		usuario.setEndereco(endereco);

		
		User user = new User(usuarioDTO.getNomeUser(), usuarioDTO.getEmail(),
				encoder.encode(usuarioDTO.getPassword()));

		Set<String> strRoles = usuarioDTO.getRoles();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(RoleEnum.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Erro: Role não encontrada."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(RoleEnum.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Erro: Role não encontrada."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRepository.findByName(RoleEnum.ROLE_MODERATOR)
					.orElseThrow(() -> new RuntimeException("Erro: Role não encontrada."));
					roles.add(modRole);
					
					break;
				default:
					Role userRole = roleRepository.findByName(RoleEnum.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Erro: Role não encontrada."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);
		usuario.setUser(user);
		usuarioRepository.save(usuario);
		fotoService.cadastrarFotoUsuario(foto, usuario);
		usuarioDTO.setUrl(adicionarImagemUri(usuario));
		
		//Foto fotoUsuario = new Foto();
		
		if(usuario.getVenda() == true && usuario.getCompra() == false ) { // será somente vendedor ou funcionario
			
			
			
			
			
			
			
		}else if(usuario.getVenda() == false && usuario.getCompra() == true) { // será somente comprador ou cliente
			
			
			
		}else if(usuario.getVenda() == true && usuario.getCompra() == true) { // sera comprador e vendedor
			
			
			
		}
		
		
		
		return usuarioDTO;
	}

	private String adicionarImagemUri(Usuario usuario) {
		URI uri = ServletUriComponentsBuilder.fromCurrentContextPath().path("/usuario/{id}/foto")
				.buildAndExpand(usuario.getUsuarioId()).toUri();
		UsuarioDTO usuarioDTO = new UsuarioDTO();
		usuarioDTO.setUrl(uri.toString());
		return usuarioDTO.getUrl();
	}

	public UsuarioDTO atualizarUsuario(Integer id, UsuarioDTO usuarioSolicitado) {
		Usuario usuarioExistente = usuarioRepository.findById(id).orElse(null);
		if (usuarioExistente != null) {
			usuarioExistente.setNome(usuarioSolicitado.getNome());
			//usuarioExistente.setNomeUser(usuarioSolicitado.getNomeUser());
			usuarioExistente.setTelefone(usuarioSolicitado.getTelefone());
			//usuarioExistente.setEmail(usuarioSolicitado.getEmail());
			usuarioExistente.setCpf(usuarioSolicitado.getCpf());
			usuarioExistente.setCompra(usuarioSolicitado.isCompra());
			usuarioExistente.setVenda(usuarioSolicitado.isVenda());
			usuarioExistente.setData(usuarioSolicitado.getData());
			usuarioExistente.getUser().setUsername(usuarioSolicitado.getNomeUser());
			usuarioExistente.getUser().setEmail(usuarioSolicitado.getEmail());
			
			RestTemplate restTemplate = new RestTemplate();
			String uri = "http://viacep.com.br/ws/{cep}/json";
			Map<String, String> params = new HashMap<>();
			params.put("cep", usuarioSolicitado.getCep());
			Endereco endCadastro = restTemplate.getForObject(uri, Endereco.class, params);

			Endereco endereco = new Endereco();
			endereco.setCep(usuarioSolicitado.getCep());
			endereco.setLogradouro(endCadastro.getLogradouro());
			endereco.setComplemento(usuarioSolicitado.getComplemento());
			endereco.setBairro(endCadastro.getBairro());
			endereco.setLocalidade(endCadastro.getLocalidade());
			endereco.setUf(endCadastro.getUf());
			endereco.setNumero(usuarioSolicitado.getNumero());

			enderecoRepository.save(endereco);

			
			usuarioRepository.save(usuarioExistente);
			return usuarioSolicitado;
		
		} else {
			throw new IllegalArgumentException("Usuário não encontrado");
		}
	}

	public void deletarUsuario(Integer id) {
		Usuario usuarioExistente = usuarioRepository.findById(id).orElse(null);
		if (usuarioExistente != null) {
			usuarioRepository.delete(usuarioExistente);
		} else {
			throw new IllegalArgumentException("Usuário não existente");
		}
	}
	
}


// Colocar esse código dentro do metodo que precisa salvar a info com data e
// hora
//	String strLocalDateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//	LocalDateTime data = LocalDateTime.parse(strLocalDateTime, DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//	"usuario".setData(LocalDateTime.now());
