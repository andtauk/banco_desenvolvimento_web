package br.com.api.g2.dto;

import java.time.LocalDate;
import java.util.Set;

import br.com.api.g2.domain.Foto;

public class UsuarioDTO {
	

	private String nome;
	private String nomeUser;
	private String telefone;
	private String email;
	private String cpf;
	private boolean compra;
	private boolean venda;
	private LocalDate data;
	private String cep;
	private String numero;
	private String complemento;
	//private Foto foto;
	private String password;
	private Set<String> roles;
	private String url;

	public UsuarioDTO() {
	}

	public UsuarioDTO(String nome, String nomeUser, String telefone, String email, String cpf, boolean compra,
			boolean venda, LocalDate data, String cep, String numero, String complemento, String password,
			Set<String> roles, String url) {
		super();
		this.nome = nome;
		this.nomeUser = nomeUser;
		this.telefone = telefone;
		this.email = email;
		this.cpf = cpf;
		this.compra = compra;
		this.venda = venda;
		this.data = data;
		this.cep = cep;
		this.numero = numero;
		this.complemento = complemento;
		this.password = password;
		this.roles = roles;
		this.url = url;
	}

	public String getPassword() {
		return password;
	}
	//teste
	public UsuarioDTO(String nome, String nomeUser, String telefone, String email, String cpf, boolean compra,
			boolean venda, LocalDate data, String cep, String numero, String complemento, Foto foto) {
		this.nome = nome;
		this.nomeUser = nomeUser;
		this.telefone = telefone;
		this.email = email;
		this.cpf = cpf;
		this.compra = compra;
		this.venda = venda;
		this.data = data;
		this.cep = cep;
		this.numero = numero;
		this.complemento = complemento;
		//this.foto = foto;
		
	}


	public void setPassword(String password) {
		this.password = password;
	}


	public Set<String> getRoles() {
		return roles;
	}

	public void setRoles(Set<String> roles) {
		this.roles = roles;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}


	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getNomeUser() {
		return nomeUser;
	}

	public void setNomeUser(String nomeUser) {
		this.nomeUser = nomeUser;
	}

	public String getTelefone() {
		return telefone;
	}

	public void setTelefone(String telefone) {
		this.telefone = telefone;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getCpf() {
		return cpf;
	}

	public void setCpf(String cpf) {
		this.cpf = cpf;
	}

	public boolean isCompra() {
		return compra;
	}

	public void setCompra(boolean compra) {
		this.compra = compra;
	}

	public boolean isVenda() {
		return venda;
	}

	public void setVenda(boolean venda) {
		this.venda = venda;
	}

	public LocalDate getData() {
		return data;
	}

	public void setData(LocalDate data) {
		this.data = data;
	}

	public String getCep() {
		return cep;
	}

	public void setCep(String cep) {
		this.cep = cep;
	}

	public String getNumero() {
		return numero;
	}

	public void setNumero(String numero) {
		this.numero = numero;
	}

	public String getComplemento() {
		return complemento;
	}

	public void setComplemento(String complemento) {
		this.complemento = complemento;
	}



	/*public Foto getFoto() {
		return foto;
	}*/



	/*public void setFoto(Foto foto) {
		this.foto = foto;
	}*/

	




	
	
	
}
