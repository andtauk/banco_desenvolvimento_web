package br.com.api.g2.domain;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "foto")
public class Foto {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "foto_cd_id")
	private Integer fotoId;

	@Lob
	@Column(name = "foto_tx_dados")
	private byte[] dados;

	@Column(name = "foto_tx_tipo")
	private String tipo;

	@Column(name = "foto_tx_nome")
	private String nome;

	@OneToOne
	@JoinColumn(name = "fk_usu_cd_id")
	private Usuario usuario;

	@OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
	@JoinColumn(name = "fk_pro_cd_id")
	private Produto produto;

	public Foto() {

	}

	public Foto(Integer fotoId, byte[] dados, String tipo, String nome, Usuario usuario, Produto produto) {
		this.fotoId = fotoId;
		this.dados = dados;
		this.tipo = tipo;
		this.nome = nome;
		this.usuario = usuario;
		this.produto = produto;
	}

	//public Foto(Integer fotoId, byte[] dados, String tipo, String nome, Produto produto) {
	//	this.fotoId = fotoId;
	//	this.dados = dados;
	//	this.tipo = tipo;
	//	this.nome = nome;
	//	this.produto = produto;
	//}

	public Integer getFotoId() {
		return fotoId;
	}

	public void setFotoId(Integer fotoId) {
		this.fotoId = fotoId;
	}

	public byte[] getDados() {
		return dados;
	}

	public void setDados(byte[] dados) {
		this.dados = dados;
	}

	public String getTipo() {
		return tipo;
	}

	public void setTipo(String tipo) {
		this.tipo = tipo;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public Produto getProduto() {
		return produto;
	}

	public void setProduto(Produto produto) {
		this.produto = produto;
	}

	public Usuario getUsuario() {
		return usuario;
	}

	public void setUsuario(Usuario usuario) {
		this.usuario = usuario;
	}

}
