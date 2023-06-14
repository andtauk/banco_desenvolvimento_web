package br.com.api.g2.domain;

import java.time.LocalDate;
import java.util.List;

import org.hibernate.validator.constraints.br.CPF;

import com.fasterxml.jackson.annotation.JsonFormat;

import br.com.api.g2.security.domain.User;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Entity
@Table(name = "usuario")
public class Usuario {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "usu_cd_id", nullable = false)
	@Schema(requiredMode = Schema.RequiredMode.REQUIRED, defaultValue = "Identificador unico do usuario")
	private Integer usuarioId;

	@Column(name = "usu_tx_nome")
	@NotBlank(message = "O nome do usuário é obrigatório.")
	@NotNull(message = "O nome do usuário é obrigatório.")
	private String nome;

	//@Column(name = "usu_tx_nome_user")
	//@NotBlank(message = "O user é obrigatório.")
	//@NotNull(message = "O user é obrigatório.")
	//private String nomeUser;

	@Column(name = "usu_tx_telefone")
	@NotBlank(message = "O telefone é obrigatório.")
	@NotNull(message = "O telefone é obrigatório.")
	private String telefone;

	//@Column(name = "usu_tx_email")
	//@NotNull(message = "O email é obrigatório.")
	//@NotBlank(message = "O email é obrigatório.")
	//@Email(message = "O email deve ser válido.")
	//@Pattern(regexp = ".+@.+\\.com+", message = "Por favor insira um email válido")
	//private String email;

	@Column(name = "usu_tx_cpf")
	@NotNull(message = "O CPF é obrigatório.")
	@NotBlank(message = "O CPF é obrigatório.")
	@CPF(message = "O CPF deve ser válido.")
	@Pattern(regexp = "\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}", message = "O CPF deve estar no formato correto: xxx.xxx.xxx-xx")
	private String cpf;

	@Column(name = "usu_bl_compra") // comprador ou cliente
	private Boolean compra;

	@Column(name = "usu_bl_venda") // vendedor ou funconario
	private Boolean venda;

	// adiciona a data e hora
	@Temporal(TemporalType.DATE)
	@JsonFormat(pattern = "yyyy-MM-dd")
	@Column(name = "usu_dt_nascimento", nullable = false)
	private LocalDate data;

	// Muitos usuarios tem mt endereço
	@ManyToOne
	@JoinColumn(name = "fk_end_cd_id")
	private Endereco endereco;

//	// Um usuario tem muitos produtos
//	@OneToMany(mappedBy = "usuario")
//	private List<Produto> produtos;

//	// um usuario tem muitos pedidos
//	@OneToMany(mappedBy = "usuario")
//	private List<Pedido> pedido;
	
	@OneToOne
	@JoinColumn(name = "fk_id")
	private User user;

	public Usuario() {

	}

	public Usuario(Integer usuarioId, String nome, String telefone, String cpf,
			Boolean compra, Boolean venda, LocalDate data, Endereco endereco) {
		this.usuarioId = usuarioId;
		this.nome = nome;
		//this.nomeUser = nomeUser;
		this.telefone = telefone;
		//this.email = email;
		this.cpf = cpf;
		this.compra = compra;
		this.venda = venda;
		this.data = data;
		this.endereco = endereco;
	}

	public Integer getUsuarioId() {
		return usuarioId;
	}

	public void setUsuarioId(Integer usuarioId) {
		this.usuarioId = usuarioId;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getTelefone() {
		return telefone;
	}

	public void setTelefone(String telefone) {
		this.telefone = telefone;
	}

	public String getCpf() {
		return cpf;
	}

	public void setCpf(String cpf) {
		this.cpf = cpf;
	}

	public Boolean getCompra() {
		return compra;
	}

	public void setCompra(Boolean compra) {
		this.compra = compra;
	}

	public Boolean getVenda() {
		return venda;
	}

	public void setVenda(Boolean venda) {
		this.venda = venda;
	}

	public LocalDate getData() {
		return data;
	}

	public void setData(LocalDate data) {
		this.data = data;
	}

	public Endereco getEndereco() {
		return endereco;
	}

	public void setEndereco(Endereco endereco) {
		this.endereco = endereco;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}
	
	

}
