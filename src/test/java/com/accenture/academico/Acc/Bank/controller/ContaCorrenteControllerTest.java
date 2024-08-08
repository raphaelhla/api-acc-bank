package com.accenture.academico.Acc.Bank.controller;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import com.accenture.academico.Acc.Bank.dto.ContaCorrenteRequestDTO;
import com.accenture.academico.Acc.Bank.dto.ContaCorrenteResponseDTO;
import com.accenture.academico.Acc.Bank.dto.SaqueDepositoRequestDTO;
import com.accenture.academico.Acc.Bank.dto.TransferenciaRequestDTO;
import com.accenture.academico.Acc.Bank.exception.contacorrente.ContaCorrenteComSaldoException;
import com.accenture.academico.Acc.Bank.exception.contacorrente.ContaCorrenteJaCadastradoException;
import com.accenture.academico.Acc.Bank.exception.contacorrente.ContaCorrenteNaoEncontradaException;
import com.accenture.academico.Acc.Bank.exception.contacorrente.SaldoInsuficienteException;
import com.accenture.academico.Acc.Bank.exception.contacorrente.TransferenciaEntreContasIguaisException;
import com.accenture.academico.Acc.Bank.exception.contacorrente.ValorInvalidoException;
import com.accenture.academico.Acc.Bank.handler.ResponseError;
import com.accenture.academico.Acc.Bank.model.Agencia;
import com.accenture.academico.Acc.Bank.model.Cliente;
import com.accenture.academico.Acc.Bank.model.ContaCorrente;
import com.accenture.academico.Acc.Bank.repository.AgenciaRepository;
import com.accenture.academico.Acc.Bank.repository.ClienteRepository;
import com.accenture.academico.Acc.Bank.repository.ContaCorrenteRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Testes do controlador de Contas Correntes")
class ContaCorrenteControllerTest {

	@Autowired
	private ContaCorrenteRepository contaCorrenteRepository;
	
	@Autowired
    private AgenciaRepository agenciaRepository;
	
	@Autowired
    private ClienteRepository clienteRepository;
	
	@Autowired
    private MockMvc mockMvc;
	
	ObjectMapper objectMapper = new ObjectMapper();
	
	Agencia agencia1;
	Agencia agencia2;
	Cliente cliente1;
	Cliente cliente2;
	
	private ContaCorrente conta;
	private ContaCorrenteRequestDTO contaRequestDTO;
	
    @BeforeEach
    void setUp() {
    	agencia1 = agenciaRepository.save(new Agencia(null, "Agencia 1", "Endereco 1", "123456789"));
    	agencia2 = agenciaRepository.save(new Agencia(null, "Agencia 2", "Endereco 2", "987654321"));
    	
    	cliente1 = clienteRepository.save(new Cliente(null, "Raphael Agra", "11122233345", "83987372109", null));
    	cliente2 = clienteRepository.save(new Cliente(null, "Biu Silva", "55566677789", "83987872511", null));
    	
    	conta = contaCorrenteRepository.save(new ContaCorrente(agencia1, cliente1));
    	conta.setNumero(Long.toString(conta.getId() + 10000));
    	conta = contaCorrenteRepository.save(conta);
    	
    	contaRequestDTO = new ContaCorrenteRequestDTO(cliente1.getId(), agencia1.getId());
    }
    
    @AfterEach
    void tearDown() {
    	contaCorrenteRepository.deleteAll();
    	clienteRepository.deleteAll();
    	agenciaRepository.deleteAll();
    }
    
    @Nested
    @DisplayName("Conjunto casos de teste do endpoint Criar")
    class ContaCorrenteFluxosBasicosCriar{
    	
    	@Test
        @DisplayName("Quando criamos uma conta corrente com dados válidos")
        void quandoCriarContaCorrenteValida() throws Exception {
            // Arrange
        	contaCorrenteRepository.delete(conta);
    		
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(contaRequestDTO)))
                .andExpect(status().isCreated())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ContaCorrenteResponseDTO resultado = objectMapper.readValue(responseJsonString, ContaCorrenteResponseDTO.class);
            
            // Assert
            assertNotNull(resultado.getId());
            assertEquals(BigDecimal.valueOf(10000L + resultado.getId()).toString(), resultado.getNumero());
            assertEquals(BigDecimal.ZERO, resultado.getSaldo());
            assertEquals(agencia1.getId(), resultado.getAgencia().getId());
        }
        
        @Test
        @DisplayName("Quando criamos uma conta corrente para cliente que ja possui conta")
        void quandoCriarContaCorrenteClienteJaPossuiConta() throws Exception {
            // Arrange
        	
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(contaRequestDTO)))
                .andExpect(status().isConflict())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteJaCadastradoException exception = new ContaCorrenteJaCadastradoException(contaRequestDTO.getIdCliente());
            
            // Assert
            assertEquals(exception.getMessage(), resultado.getMessage());
        }
        
        @Test
        @DisplayName("Quando criamos uma conta corrente com idCliente nulo")
        void quandoCriarContaCorrenteIdClienteNulo() throws Exception {
            // Arrange
        	contaRequestDTO.setIdCliente(null);
        	
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(contaRequestDTO)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            
            // Assert
            assertAll(
                    () -> assertEquals("Erros de validacao encontrados", resultado.getMessage()),
                    () -> assertEquals("Campo idCliente obrigatorio", resultado.getErrors().get(0))
            );
        }
        
        @Test
        @DisplayName("Quando criamos uma conta corrente com idAgencia nulo")
        void quandoCriarContaCorrenteIdAgenciaNulo() throws Exception {
            // Arrange
        	contaRequestDTO.setIdAgencia(null);
        	
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(contaRequestDTO)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            
            // Assert
            assertAll(
                    () -> assertEquals("Erros de validacao encontrados", resultado.getMessage()),
                    () -> assertEquals("Campo idAgencia obrigatorio", resultado.getErrors().get(0))
            );
        }
    }

    @Nested
    @DisplayName("Conjunto casos de teste do endpoint Buscar")
    class AgenciaFluxosBasicosBuscar{
    	
    	@Test
        @DisplayName("Quando buscamos uma conta corrente salva pelo id")
        void quandoBuscamosContaCorrenteValida() throws Exception {
        	// Arrange
        	
            // Act
            String responseJsonString = mockMvc.perform(get("/contas-correntes/" + conta.getId())
            			.contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ContaCorrenteResponseDTO resultado = objectMapper.readValue(responseJsonString, ContaCorrenteResponseDTO.class);
            
            // Assert
            assertEquals(conta.getId(), resultado.getId());
            assertEquals(conta.getNumero(), resultado.getNumero());
            assertEquals(conta.getSaldo().compareTo(resultado.getSaldo()), 0);
            assertEquals(conta.getAgencia().getId(), resultado.getAgencia().getId());
        }
    	
    	@Test
        @DisplayName("Quando buscamos uma conta corrente inexistente pelo id")
        void quandoBuscamosContaCorrenteInexistente() throws Exception {
        	// Arrange
        	Long idInexistente = 999L;
    		
            // Act
            String responseJsonString = mockMvc.perform(get("/contas-correntes/" + idInexistente)
            			.contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteNaoEncontradaException exception = new ContaCorrenteNaoEncontradaException(idInexistente);
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    }
    
    @Nested
    @DisplayName("Conjunto casos de teste do endpoint Remover")
    class ContaCorrenteFluxosBasicosRemover{
    	
    	@Test
        @DisplayName("Quando removemos uma conta corrente pelo id")
        void quandoRemovemosContaCorrenteValida() throws Exception {
        	// Arrange
        	
            // Act
            String responseJsonString = mockMvc.perform(delete("/contas-correntes/" + conta.getId())
            			.contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            // Assert
            assertTrue(responseJsonString.isBlank());
        }
    	
    	@Test
        @DisplayName("Quando removemos uma conta corrente inexistente")
        void quandoRemovemosContaCorrenteInexistente() throws Exception {
        	// Arrange
        	Long idInexistente = 999L;
    		
            // Act
            String responseJsonString = mockMvc.perform(delete("/contas-correntes/" + idInexistente)
            			.contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteNaoEncontradaException exception = new ContaCorrenteNaoEncontradaException(idInexistente);
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando removemos uma conta corrente com saldo")
        void quandoRemovemosContaCorrenteComSaldo() throws Exception {
        	// Arrange
    		conta.depositar(BigDecimal.valueOf(10));
    		contaCorrenteRepository.save(conta);
    		
    		
            // Act
            String responseJsonString = mockMvc.perform(delete("/contas-correntes/" + conta.getId())
            			.contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteComSaldoException exception = new ContaCorrenteComSaldoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    }
    
    @Nested
    @DisplayName("Conjunto casos de teste do endpoint Sacar")
    class ContaCorrenteFluxosBasicosSacar{
    	
    	private SaqueDepositoRequestDTO saqueDTO;
    	
    	@BeforeEach
    	void setUp() {
    		conta.depositar(BigDecimal.valueOf(20));
    		contaCorrenteRepository.save(conta);
    		
    		saqueDTO = new SaqueDepositoRequestDTO(BigDecimal.valueOf(5), null);
    	}
    	
    	@Test
        @DisplayName("Quando sacamos um valor valido de uma conta corrente")
        void quandoSacamosValorValidoContaCorrente() throws Exception {
        	// Arrange
        	saqueDTO.setValor(BigDecimal.valueOf(5.57));
    		
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/sacar")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(saqueDTO)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ContaCorrente contaAtualizada = contaCorrenteRepository.findById(conta.getId()).orElseThrow();
            
            // Assert
            assertTrue(responseJsonString.isBlank());
            System.out.println(conta.getSaldo());
            assertEquals(0, contaAtualizada.getSaldo().compareTo(BigDecimal.valueOf(14.43)));
        }
    	
    	@Test
        @DisplayName("Quando sacamos um valor valido de uma conta corrente inexistente")
        void quandoSacamosValorValidoContaCorrenteInexistente() throws Exception {
        	// Arrange
        	Long idInexistente = 999L;
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + idInexistente + "/sacar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(saqueDTO)))
            .andExpect(status().isNotFound())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteNaoEncontradaException exception = new ContaCorrenteNaoEncontradaException(idInexistente);
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando sacamos um valor igual a zero de uma conta corrente")
        void quandoSacamosValorIgualAZeroValidoContaCorrente() throws Exception {
        	// Arrange
        	saqueDTO.setValor(BigDecimal.valueOf(0));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/sacar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(saqueDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ValorInvalidoException exception = new ValorInvalidoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando sacamos um valor negativo de uma conta corrente")
        void quandoSacamosValorNegativoContaCorrente() throws Exception {
        	// Arrange
        	saqueDTO.setValor(BigDecimal.valueOf(-1));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/sacar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(saqueDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ValorInvalidoException exception = new ValorInvalidoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando sacamos um valor maior que o saldo de uma conta corrente")
        void quandoSacamosValorMaiorQueSaldoContaCorrente() throws Exception {
        	// Arrange
        	saqueDTO.setValor(BigDecimal.valueOf(20.01));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/sacar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(saqueDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            SaldoInsuficienteException exception = new SaldoInsuficienteException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    }
    
    @Nested
    @DisplayName("Conjunto casos de teste do endpoint Depositar")
    class ContaCorrenteFluxosBasicosDepositar{
    	
    	private SaqueDepositoRequestDTO depositoDTO;
    	
    	@BeforeEach
    	void setUp() {
    		depositoDTO = new SaqueDepositoRequestDTO(BigDecimal.valueOf(5), null);
    	}
    	
    	@Test
        @DisplayName("Quando depositamos um valor valido de uma conta corrente")
        void quandoDepositamosValorValidoContaCorrente() throws Exception {
        	// Arrange
        	depositoDTO.setValor(BigDecimal.valueOf(5.57));
    		
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/depositar")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(depositoDTO)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ContaCorrente contaAtualizada = contaCorrenteRepository.findById(conta.getId()).orElseThrow();
            
            // Assert
            assertTrue(responseJsonString.isBlank());
            assertEquals(0, contaAtualizada.getSaldo().compareTo(depositoDTO.getValor()));
        }
    	
    	@Test
        @DisplayName("Quando depositamos um valor valido de uma conta corrente inexistente")
        void quandoDepositamosValorValidoContaCorrenteInexistente() throws Exception {
        	// Arrange
        	Long idInexistente = 999L;
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + idInexistente + "/depositar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(depositoDTO)))
            .andExpect(status().isNotFound())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteNaoEncontradaException exception = new ContaCorrenteNaoEncontradaException(idInexistente);
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando depositamos um valor igual a zero de uma conta corrente")
        void quandoDepositamosValorIgualAZeroValidoContaCorrente() throws Exception {
        	// Arrange
        	depositoDTO.setValor(BigDecimal.valueOf(0));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/depositar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(depositoDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ValorInvalidoException exception = new ValorInvalidoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando depositamos um valor negativo de uma conta corrente")
        void quandoDepositamosValorNegativoContaCorrente() throws Exception {
        	// Arrange
        	depositoDTO.setValor(BigDecimal.valueOf(-1));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/depositar")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(depositoDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ValorInvalidoException exception = new ValorInvalidoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    }

    @Nested
    @DisplayName("Conjunto casos de teste do endpoint Transferir")
    class ContaCorrenteFluxosBasicosTransferir{
    	
    	private ContaCorrente conta2;
    	private TransferenciaRequestDTO transferenciaDTO;
    	
    	@BeforeEach
    	void setUp() {
    		conta.depositar(BigDecimal.valueOf(20));
    		contaCorrenteRepository.save(conta);
    		
    		conta2 = contaCorrenteRepository.save(new ContaCorrente(agencia2, cliente2));
    		conta2.setNumero(Long.toString(conta2.getId() + 10000));
        	conta2 = contaCorrenteRepository.save(conta2);
    		
    		transferenciaDTO = new TransferenciaRequestDTO(BigDecimal.valueOf(5), null, conta2.getNumero());
    	}
    	
    	@Test
        @DisplayName("Quando realizamos uma transferencia valida")
        void quandoTransferenciaValidaContaCorrente() throws Exception {
        	// Arrange
        	transferenciaDTO.setValor(BigDecimal.valueOf(5.57));
    		
            // Act
            String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/transferir")
            			.contentType(MediaType.APPLICATION_JSON)
            			.content(objectMapper.writeValueAsString(transferenciaDTO)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
            
            ContaCorrente contaOrigemAtualizada = contaCorrenteRepository.findById(conta.getId()).orElseThrow();
            ContaCorrente contaDestinoAtualizada = contaCorrenteRepository.findByNumero(conta2.getNumero()).orElseThrow();
            
            // Assert
            assertTrue(responseJsonString.isBlank());
            assertEquals(0, contaOrigemAtualizada.getSaldo().compareTo(BigDecimal.valueOf(14.43)));
            assertEquals(0, contaDestinoAtualizada.getSaldo().compareTo(transferenciaDTO.getValor()));
        }
    	
    	@Test
        @DisplayName("Quando realizamos uma transferencia contaCorrenteOrigem inexistente")
        void quandoTransferimosContaCorrenteOrigemInexistente() throws Exception {
        	// Arrange
        	Long idInexistente = 999L;
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + idInexistente + "/transferir")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(transferenciaDTO)))
            .andExpect(status().isNotFound())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteNaoEncontradaException exception = new ContaCorrenteNaoEncontradaException(idInexistente);
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando realizamos uma transferencia contaCorrenteDestino inexistente")
        void quandoTransferimosContaCorrenteDestinoInexistente() throws Exception {
        	// Arrange
    		String numeroInexistente = "00000";
        	transferenciaDTO.setNumeroContaDestino(numeroInexistente);
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/transferir")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(transferenciaDTO)))
            .andExpect(status().isNotFound())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ContaCorrenteNaoEncontradaException exception = new ContaCorrenteNaoEncontradaException(numeroInexistente);
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando realizamos uma transferencia com valor igual a zero")
        void quandoTransferimosValorIgualAZero() throws Exception {
        	// Arrange
        	transferenciaDTO.setValor(BigDecimal.valueOf(0));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/transferir")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(transferenciaDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ValorInvalidoException exception = new ValorInvalidoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando realizamos uma transferencia com valor negativo")
        void quandoTransferimosValorNegativo() throws Exception {
        	// Arrange
        	transferenciaDTO.setValor(BigDecimal.valueOf(-1));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/transferir")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(transferenciaDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            ValorInvalidoException exception = new ValorInvalidoException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
    	@Test
        @DisplayName("Quando realizamos uma transferencia entre contas iguais")
        void quandoTransferimosEntreContasIguais() throws Exception {
        	// Arrange
        	transferenciaDTO.setNumeroContaDestino(conta.getNumero());
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/transferir")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(transferenciaDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            TransferenciaEntreContasIguaisException exception = new TransferenciaEntreContasIguaisException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    	
       	@Test
        @DisplayName("Quando realizamos uma transferencia com valor maior que o saldo")
        void quandoTransferimosValorMaiorQueSaldo() throws Exception {
        	// Arrange
       		transferenciaDTO.setValor(BigDecimal.valueOf(20.01));
    		
            // Act
        	String responseJsonString = mockMvc.perform(post("/contas-correntes/" + conta.getId() + "/transferir")
        			.contentType(MediaType.APPLICATION_JSON)
        			.content(objectMapper.writeValueAsString(transferenciaDTO)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
            
            ResponseError resultado = objectMapper.readValue(responseJsonString, ResponseError.class);
            SaldoInsuficienteException exception = new SaldoInsuficienteException();
            
            // Assert
            assertEquals(exception.getMessage() , resultado.getMessage());
        }
    }
}
