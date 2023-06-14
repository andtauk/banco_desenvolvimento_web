package br.com.api.g2.exceptions;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;



@ControllerAdvice
public class ControllerExceptionHandler extends ResponseEntityExceptionHandler {

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		
		List<String> erros = new ArrayList<>();
		for(FieldError error:ex.getBindingResult().getFieldErrors()) {
			erros.add(error.getField()+ ":" +error.getDefaultMessage()); //verifica o campo respectivo do erro
		}
		
		ErroResposta erro = new ErroResposta(status.value(), "Preencha todos os campos", LocalDateTime.now(), erros);
		return super.handleExceptionInternal(ex, erro, headers, status, request);
	}
}