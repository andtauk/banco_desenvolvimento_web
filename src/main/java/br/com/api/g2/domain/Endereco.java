package br.com.api.g2.domain;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Entity
@Table(name="endereco")
public class Endereco {

	@Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name= "end_cd_id")
	@Schema(requiredMode = Schema.RequiredMode.REQUIRED, defaultValue= "Identificador unico do endereço")
	private Integer enderecoId;
	
	@NotBlank(message="O campo numero é obrigatório.")
	@NotNull(message="O campo numero é obrigatório.")
	@Column(name= "end_tx_num")
	private String numero;
	
	@Column(name="end_tx_cep")
	@NotBlank(message="O campo CEP é obrigatório.")
	@NotNull(message="O campo CEP é obrigatório.")
	@Pattern(regexp="[0-9]{5}-[0-9]{3}", message="O CEP deve estar no formato 99999-999.")
	private String cep;
	
	@Column(name="end_tx_logradouro")
	@NotBlank(message="O campo logradouro é obrigatório.")
	@NotNull(message="O campo logradouro é obrigatório.")
	private String logradouro;
	
	@Column(name="end_tx_complem")
	private String complemento;
	
	@Column(name="end_tx_bairro")
	@NotBlank(message="O campo bairro é obrigatório.")
	@NotNull(message="O nome da bairro é obrigatório.")
	private String bairro;
	
	@Column(name="end_tx_localidade")
	@NotBlank(message="O campo localidade é obrigatório.")
	@NotNull(message="O campo localidade é obrigatório.")
	private String localidade;
	
	@Column(name="end_tx_uf")
	@NotBlank(message="O campo uf é obrigatório.")
	@NotNull(message="O campo uf é obrigatório.")
	private String uf;
	
	//Um endereço tem muitos usuarios
	@OneToMany(mappedBy="endereco")
	private List<Usuario> usuarios;
	
	public Endereco() {	
	}

	public Endereco(Integer enderecoId, String numero, String cep,String logradouro,String complemento,String bairro,String localidade,String uf) {
		this.enderecoId = enderecoId;
		this.numero = numero;
		this.cep = cep;
		this.logradouro = logradouro;
		this.complemento = complemento;
		this.bairro = bairro;
		this.localidade = localidade;
		this.uf = uf;
	}

	public Integer getEnderecoId() {
		return enderecoId;
	}

	public void setEnderecoId(Integer enderecoId) {
		this.enderecoId = enderecoId;
	}

	public String getNumero() {
		return numero;
	}

	public void setNumero(String numero) {
		this.numero = numero;
	}

	public String getCep() {
		return cep;
	}

	public void setCep(String cep) {
		this.cep = cep;
	}

	public String getLogradouro() {
		return logradouro;
	}

	public void setLogradouro(String logradouro) {
		this.logradouro = logradouro;
	}

	public String getComplemento() {
		return complemento;
	}

	public void setComplemento(String complemento) {
		this.complemento = complemento;
	}

	public String getBairro() {
		return bairro;
	}

	public void setBairro(String bairro) {
		this.bairro = bairro;
	}

	public String getLocalidade() {
		return localidade;
	}

	public void setLocalidade(String localidade) {
		this.localidade = localidade;
	}

	public String getUf() {
		return uf;
	}

	public void setUf(String uf) {
		this.uf = uf;
	}

	
}
