package com.accenture.academico.Acc.Bank.exception.contacorrente;

import org.springframework.http.HttpStatus;

import com.accenture.academico.Acc.Bank.exception.BancoException;

public class ContaComSaldoException extends BancoException{

	public ContaComSaldoException() {
		super("Nao eh possivel remover uma conta que possui saldo");
        this.httpStatus = HttpStatus.BAD_REQUEST;
	}
}
