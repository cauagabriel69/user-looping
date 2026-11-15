# user-looping

# Automação de Requisições em API com Rotação Turbo de IP

Script em Python desenvolvido com arquitetura **Produtor-Consumidor multithread** para automação e testes de estresse de requisições HTTP diretas (`POST` em JSON) na rota `/api/auth/register`, operando exclusivamente via sessões de rede (`requests.Session`) sem sobrecarga de navegadores headless.

---

## Principais Funcionalidades

* **Arquitetura Produtor-Consumidor Assíncrona:** Enquanto um pool de *workers* consome IPs validados para enviar os payloads JSON, uma thread em segundo plano gerencia até **100 threads simultâneas** para testar novos proxies contra o domínio alvo.
* **Coleta Massiva e Desduplicação em Memória:** Baixa listas de proxies (`HTTP`, `SOCKS4` e `SOCKS5`) em paralelo de múltiplos repositórios e APIs públicas, filtrando endereços repetidos através de conjuntos (`set`) protegidos por `threading.Lock`.
* **Validação Prévia de Túnel SSL/Cloudflare:** Antes de entregar um proxy a um *worker*, o scanner realiza uma requisição `HEAD` com *timeout* curto (2.5s) para confirmar que o túnel HTTPS (porta 443) atravessa bloqueios de WAF/Cloudflare sem erros (`403`, `429`, `502`, `503`, `520`, `521`, `522`).
* **Isolamento Nativo de Circuitos Tor (`IsolateSOCKSAuth`):** Gera credenciais SOCKS5 aleatórias a cada requisição no protocolo `socks5h://`, forçando o serviço local do Tor a abrir um novo circuito e trocar o IP de saída instantaneamente sem precisar reiniciar o serviço.
* **Máquina de Estados Resiliente:**
  * **`200` / `201 Created`:** Contabiliza o cadastro, avança para o próximo identificador sequencial e rotaciona o IP preventivamente.
  * **`403` / `429` (Rate Limit / WAF):** Preserva o número do usuário atual, descarta a sessão bloqueada, aloca um novo IP imediatamente e repete a tentativa.
  * **`400` / `409` / `422` (Conflito):** Identifica se o nome de usuário já existe no banco, mantém o proxy funcional atual e avança apenas o contador de usuário.
  * **Falhas de Rede / Timeout:** Substitui o proxy defeituoso na hora sem pular o número do usuário na fila.

---

## Modos de Rotação de IP

Durante a inicialização, o menu interativo permite escolher entre 4 motores de conexão:

1. **Modo 1 — Scanner Turbo de Proxies:** Usa exclusivamente a fila de alta velocidade abastecida pelas 100 threads de verificação de proxies públicos (`HTTP`, `SOCKS4` e `SOCKS5`).
2. **Modo 2 — Tor com Isolamento de Circuito:** Conecta na porta local `127.0.0.1:9050` via `socks5h://` (com resolução de DNS remota para evitar *DNS Leak*), injetando um par `usuario:senha` exclusivo por tentativa para garantir um *Exit Node* diferente.
3. **Modo 3 — Híbrido (Scanner Turbo + Failover Tor):** Prioriza os proxies validados da fila rápida (`get_nowait()`) e, caso a fila esvazie momentaneamente, aciona automaticamente um circuito isolado do Tor para manter os *workers* operando sem ociosidade.
4. **Modo 4 — Conexão Direta (Sem Proxy):** Dispara as requisições usando o IP local da máquina e mantém a conexão TCP aberta (`keep-alive`) para testes de rota.

---

## Pré-requisitos e Instalação

### 1. Clonar o repositório
```bash
git clone [https://github.com/cauagabriel69/user-looping.git](https://github.com/cauagabriel69/user-looping.git)
cd user-looping