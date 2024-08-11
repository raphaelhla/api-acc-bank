package com.accenture.academico.Acc.Bank.exception.agencia;

import org.springframework.http.HttpStatus;

import com.accenture.academico.Acc.Bank.exception.BancoException;

public class AgenciaJaCadastradaException extends BancoException {

    public AgenciaJaCadastradaException(String campo, String cpf) {
        super(String.format("Ja existe uma agencia cadastrada com o %s %s", campo, cpf));
        this.httpStatus = HttpStatus.CONFLICT;
    }
}
