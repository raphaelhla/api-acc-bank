package com.accenture.academico.Acc.Bank.exception.contacorrente;

import org.springframework.http.HttpStatus;

import com.accenture.academico.Acc.Bank.exception.BancoException;

public class ContaCorrenteNaoEncontradaException extends BancoException{

	public ContaCorrenteNaoEncontradaException(Long idConta) {
		super(String.format("Conta corrente com ID %d não encontrada.", idConta));
        this.httpStatus = HttpStatus.NOT_FOUND;
	}
	
	public ContaCorrenteNaoEncontradaException(String numeroConta) {
		super(String.format("Conta corrente com número %s não encontrada.", numeroConta));
        this.httpStatus = HttpStatus.NOT_FOUND;
	}
}
