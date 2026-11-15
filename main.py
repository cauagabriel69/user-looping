from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import random
import re
import socket
import threading
import time
from urllib.parse import urlparse
import requests
import urllib3

# Desativa avisos de certificado SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tenta importar a biblioteca free-proxy (opcional)
try:
    from fp.fp import FreeProxy

    FREE_PROXY_DISPONIVEL = True
except ImportError:
    FREE_PROXY_DISPONIVEL = False


# Fontes massivas de proxies (HTTP, SOCKS4 e SOCKS5)
FONTES_PROXIES = [
    (
        "http",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=2000&country=all&ssl=all&anonymity=all",
    ),
    (
        "socks4",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=2000&country=all",
    ),
    (
        "socks5",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=2000&country=all",
    ),
    (
        "http",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    ),
    (
        "socks4",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    ),
    (
        "socks5",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    ),
    (
        "http",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ),
    (
        "socks4",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    ),
    (
        "socks5",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ),
]

# --- CONTROLES GLOBAIS DE SINCRONIZAÇÃO E FILA DE ALTA VELOCIDADE ---
lock_contador = threading.Lock()
lock_proxies = threading.Lock()
parar_execucao = threading.Event()

current_attempt = 1
accounts_created_sucessfully = 0

proxies_ja_consumidos = set()
ips_ja_usados_ou_testados = set()

fila_candidatos_ineditos = deque()
fila_ips_prontos = queue.Queue(maxsize=80)


def normalizar_rotas_api(url_informada):
    """Define automaticamente a rota da API (/api/auth/register) e a Origin."""
    parsed = urlparse(url_informada)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.netloc

    # Se o utilizador digitar apenas https://exemplo.com ou /register, aponta direto para /api/auth/register
    if "/api/auth/register" in parsed.path:
        api_url = url_informada
    else:
        api_url = f"{origin}/api/auth/register"

    return api_url, origin, host


def proximo_numero_usuario():
    """Reserva um número de utilizador único para um worker."""
    global current_attempt
    with lock_contador:
        num = current_attempt
        current_attempt += 1
        return num


def registrar_sucesso():
    """Incrementa o contador global de contas criadas (Status 201 Created)."""
    global accounts_created_sucessfully
    with lock_contador:
        accounts_created_sucessfully += 1
        return accounts_created_sucessfully


def porta_local_aberta(host, porta):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, porta)) == 0


def extrair_ip_da_string(proxy_str):
    limpo = re.sub(r"^[a-zA-Z0-9]+://", "", proxy_str)
    if "@" in limpo:
        limpo = limpo.split("@")[-1]
    return limpo.split(":")[0].strip()


def baixar_fonte_proxy(protocolo, url):
    encontrados = []
    try:
        sess = requests.Session()
        sess.trust_env = False
        resp = sess.get(url, timeout=4)
        if resp.status_code == 200:
            for linha in resp.text.splitlines():
                linha = linha.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", linha):
                    encontrados.append(f"{protocolo}://{linha}")
    except Exception:
        pass
    return encontrados


def abastecer_candidatos_ineditos():
    """Baixa milhares de proxies em paralelo e filtra apenas IPs nunca testados."""
    novos_brutos = []

    if FREE_PROXY_DISPONIVEL:
        try:
            lista_fp = FreeProxy(timeout=1, rand=True).get_proxy_list(repeat=False)
            novos_brutos.extend(
                [f"http://{p.strip()}" for p in lista_fp if p.strip()]
            )
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=len(FONTES_PROXIES)) as ex:
        futures = [
            ex.submit(baixar_fonte_proxy, proto, url)
            for proto, url in FONTES_PROXIES
        ]
        for fut in as_completed(futures):
            novos_brutos.extend(fut.result())

    random.shuffle(novos_brutos)

    adicionados = 0
    with lock_proxies:
        for p in novos_brutos:
            ip_entrada = extrair_ip_da_string(p)
            if (
                p not in proxies_ja_consumidos
                and ip_entrada not in ips_ja_usados_ou_testados
            ):
                proxies_ja_consumidos.add(p)
                ips_ja_usados_ou_testados.add(ip_entrada)
                fila_candidatos_ineditos.append(p)
                adicionados += 1

    print(
        f"[SCANNER] {adicionados} novos IPs inéditos carregados na fila de"
        " verificação."
    )
    return adicionados


def retirar_lote_candidatos(tamanho_lote=100):
    lote = []
    with lock_proxies:
        while fila_candidatos_ineditos and len(lote) < tamanho_lote:
            lote.append(fila_candidatos_ineditos.popleft())

    if not lote:
        abastecer_candidatos_ineditos()
        with lock_proxies:
            while fila_candidatos_ineditos and len(lote) < tamanho_lote:
                lote.append(fila_candidatos_ineditos.popleft())

    return lote


def testar_candidato_rapido(proxy_candidato, origin_url):
    """Testa se o proxy atravessa o SSL/Cloudflare do domínio alvo em menos de 2.5s."""
    try:
        sess = requests.Session()
        sess.trust_env = False
        sess.verify = False
        sess.proxies.update({"http": proxy_candidato, "https": proxy_candidato})
        sess.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        })

        # Faz um acesso rápido à origem para garantir que o túnel HTTPS (443) passa pela Cloudflare
        resp = sess.head(origin_url, timeout=2.5)
        sess.close()

        if resp.status_code not in (429, 403, 502, 503, 520, 521, 522):
            ip_entrada = extrair_ip_da_string(proxy_candidato)
            return (proxy_candidato, ip_entrada)
    except Exception:
        pass
    return None


def mantenedor_turbo_ips(origin_url):
    """100 threads testando proxies simultaneamente contra o domínio alvo."""
    with ThreadPoolExecutor(max_workers=100) as executor:
        while not parar_execucao.is_set():
            if fila_ips_prontos.qsize() < 50:
                lote = retirar_lote_candidatos(100)
                if not lote:
                    time.sleep(0.5)
                    continue

                futures = [
                    executor.submit(testar_candidato_rapido, c, origin_url)
                    for c in lote
                ]
                for fut in as_completed(futures):
                    if parar_execucao.is_set():
                        break
                    resultado = fut.result()
                    if resultado:
                        try:
                            fila_ips_prontos.put_nowait(resultado)
                        except queue.Full:
                            break
            else:
                time.sleep(0.1)


def alocar_proxy_exclusivo(modo_proxy, worker_id):
    """Entrega imediatamente um proxy validado ou novo circuito Tor."""
    if modo_proxy == "1":
        while not parar_execucao.is_set():
            try:
                return fila_ips_prontos.get(timeout=1)
            except queue.Empty:
                continue

    elif modo_proxy == "2":
        credencial_unica = (
            f"u{worker_id}_{random.randint(100000, 999999)}:"
            f"p{random.randint(100000, 999999)}"
        )
        proxy_tor_isolado = f"socks5h://{credencial_unica}@127.0.0.1:9050"
        return proxy_tor_isolado, f"TOR_{credencial_unica.split(':')[0]}"

    elif modo_proxy == "3":
        try:
            return fila_ips_prontos.get_nowait()
        except queue.Empty:
            if porta_local_aberta("127.0.0.1", 9050):
                cred = (
                    f"u{worker_id}_{random.randint(100000, 999999)}:"
                    f"p{random.randint(100000, 999999)}"
                )
                return f"socks5h://{cred}@127.0.0.1:9050", f"TOR_{cred.split(':')[0]}"
            while not parar_execucao.is_set():
                try:
                    return fila_ips_prontos.get(timeout=1)
                except queue.Empty:
                    continue

    return None, "IP_LOCAL"


def criar_sessao_api(proxy_atual, origin_url, host_domain):
    """Configura a sessão com os headers HTTP necessários."""
    sessao = requests.Session()
    sessao.trust_env = False
    sessao.verify = False

    versao_chrome = random.choice(["128", "130", "131", "157"])
    sessao.headers.update({
        "Host": host_domain,
        "Origin": origin_url,
        "Referer": f"{origin_url}/",
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "Content-Type": "application/json",
        "Connection": "keep-alive",
        "sec-ch-ua": (
            f'"Not-A.Brand";v="99", "Google Chrome";v="{versao_chrome}",'
            f' "Chromium";v="{versao_chrome}"'
        ),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            f" (KHTML, like Gecko) Chrome/{versao_chrome}.0.0.0 Safari/537.36"
        ),
    })

    if proxy_atual:
        sessao.proxies.update({"http": proxy_atual, "https": proxy_atual})
    return sessao


def email_generator():
    """Gera e-mails no formato aceite pela API."""
    dominios = ["gmail.com", "1secmail.com", "1secmail.org", "1secmail.net"]
    prefixo = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
    return f"{prefixo}{random.randint(10, 999)}@{random.choice(dominios)}"


def rotacionar_sessao_api(
    sessao_atual, modo_proxy, worker_id, origin_url, host_domain
):
    try:
        if sessao_atual:
            sessao_atual.close()
    except Exception:
        pass
    novo_proxy, novo_ip = alocar_proxy_exclusivo(modo_proxy, worker_id)
    nova_sessao = criar_sessao_api(novo_proxy, origin_url, host_domain)
    return nova_sessao, novo_proxy, novo_ip


def worker_automacao_api(
    worker_id,
    api_url,
    origin_url,
    host_domain,
    password_chars,
    email_choice,
    email_user_fixed,
    user_prefix,
    proxy_mode,
):
    """Envia POST JSON diretamente para /api/auth/register."""
    sessao = None

    try:
        sessao, proxy_ativo, ip_ativo = rotacionar_sessao_api(
            None, proxy_mode, worker_id, origin_url, host_domain
        )
        numero_usuario = proximo_numero_usuario()

        while not parar_execucao.is_set():
            current_password = "".join(
                random.choice(password_chars) for _ in range(10)
            )
            current_username = f"{user_prefix}{numero_usuario}"
            current_name = f"User {current_username}"
            current_email = (
                email_generator() if email_choice == "1" else email_user_fixed
            )

            # Request Body JSON
            payload_json = {
                "name": current_name,
                "username": current_username,
                "email": current_email,
                "password": current_password,
                "avatar": "",
            }

            try:
                sessao.cookies.clear()

                # Envia POST direto em JSON para a rota /api/auth/register configurada
                resp = sessao.post(api_url, json=payload_json, timeout=6)

                # 1. SUCESSO REAL: Status 201 Created ou 200 OK
                if resp.status_code in (200, 201):
                    total_criadas = registrar_sucesso()
                    print(
                        f"[Worker {worker_id} | IP: {ip_ativo}] [201 CREATED"
                        f" #{total_criadas}] Username: {current_username} | Name:"
                        f" {current_name} | Email: {current_email} | Password:"
                        f" {current_password}"
                    )
                    numero_usuario = proximo_numero_usuario()

                    # Se não estiver em modo local direto, já puxa o próximo IP limpo
                    if proxy_mode != "4":
                        sessao, proxy_ativo, ip_ativo = rotacionar_sessao_api(
                            sessao, proxy_mode, worker_id, origin_url, host_domain
                        )

                # 2. RATE LIMIT (429) OU BLOQUEIO CLOUDFLARE (403)
                elif resp.status_code in (429, 403):
                    retry_after = resp.headers.get("Retry-After", "bloqueado")
                    print(
                        f"[Worker {worker_id} | IP: {ip_ativo}] [RATE LIMIT"
                        f" {resp.status_code} | Retry-After: {retry_after}] Trocando IP"
                        f" imediatamente para repetir {current_username}..."
                    )
                    sessao, proxy_ativo, ip_ativo = rotacionar_sessao_api(
                        sessao, proxy_mode, worker_id, origin_url, host_domain
                    )
                    continue

                # 3. CONFLITO / UTILIZADOR JÁ EXISTE (400 / 409 / 422)
                elif resp.status_code in (400, 409, 422):
                    texto_resp = resp.text.lower()
                    if (
                        "already" in texto_resp
                        or "existe" in texto_resp
                        or "taken" in texto_resp
                        or "em uso" in texto_resp
                    ):
                        print(
                            f"[Worker {worker_id}] [AVISO] {current_username} já existe no"
                            " banco! Avançando para o próximo número..."
                        )
                        numero_usuario = proximo_numero_usuario()
                    else:
                        print(
                            f"[Worker {worker_id} | IP: {ip_ativo}] [RESPOSTA"
                            f" {resp.status_code}]: {resp.text[:120]}"
                        )
                        numero_usuario = proximo_numero_usuario()

                else:
                    sessao, proxy_ativo, ip_ativo = rotacionar_sessao_api(
                        sessao, proxy_mode, worker_id, origin_url, host_domain
                    )

            except Exception:
                if parar_execucao.is_set():
                    break
                # Proxy deu timeout ou recusou conexão -> troca na hora sem perder o número do utilizador
                sessao, proxy_ativo, ip_ativo = rotacionar_sessao_api(
                    sessao, proxy_mode, worker_id, origin_url, host_domain
                )
                continue

    finally:
        if sessao:
            try:
                sessao.close()
            except Exception:
                pass


# =====================================================================
# MENU PRINCIPAL DE CONFIGURAÇÃO
# =====================================================================
if __name__ == "__main__":
    print("\n=== AUTOMAÇÃO DIRETA NA API (/api/auth/register) ===")

    # --- 1. VALIDAÇÃO DE URL ---
    while True:
        url_input = input(
            "Digite a URL da API (Enter para"
            " 'https://exemplo.com/api/auth/register'): "
        ).strip()
        if not url_input:
            url_input = "https://exemplo.com/api/auth/register"
        if re.match(r"^https?://[^\s/$.?#].[^\s]*$", url_input):
            api_url, origin_url, host_domain = normalizar_rotas_api(url_input)
            print(f"[ROTA DEFINIDA] POST -> {api_url} (Origin: {origin_url})")
            break
        print("[ERRO] URL inválida! Comece com http:// ou https://.")

    # --- 2. CONFIGURAÇÃO DE SENHAS ---
    password = input(
        "Digite os caracteres para gerar senhas (Enter para alfanumérico"
        " padrão): "
    ).strip()
    if not password:
        password = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    # --- 3. VALIDAÇÃO DA ESCOLHA DO TIPO DE EMAIL (1 ou 2) ---
    while True:
        print("\nEscolha o tipo de email:")
        print("1. Gerar email aleatório instantâneo")
        print("2. Usar email fixo")
        email_choice = input("Digite 1 ou 2 (Enter para 1): ").strip()
        if not email_choice:
            email_choice = "1"
        if email_choice in ["1", "2"]:
            break
        print("[ERRO] Digite apenas '1' ou '2'.")

    email_user_fixed = ""
    if email_choice == "2":
        while True:
            email_user_fixed = input(
                "Digite o email fixo (ex: seu_email@gmail.com): "
            ).strip()
            if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email_user_fixed):
                break
            print("[ERRO] Formato de e-mail inválido!")

    # --- 5. CONFIGURAÇÃO DO UTILIZADOR INICIAL ---
    user_prefix = input(
        "\nDigite o prefixo do username (Enter para 'user_'): "
    ).strip()
    if not user_prefix:
        user_prefix = "user_"

    while True:
        start_number_input = input(
            f"A partir de qual número deseja iniciar o '{user_prefix}'? (Enter para"
            " 1): "
        ).strip()
        if not start_number_input:
            current_attempt = 1
            break
        if start_number_input.isdigit() and int(start_number_input) >= 0:
            current_attempt = int(start_number_input)
            break
        print("[ERRO] Digite um número inteiro válido.")

    # --- 6. MODO DE ROTAÇÃO TURBO ---
    while True:
        print("\nEscolha o motor de Rotação Rápida de IP:")
        print("1. Scanner Turbo de Proxies (100 threads testando HTTPS na origem)")
        print("2. Tor com Isolamento de Circuito (socks5h://127.0.0.1:9050)")
        print("3. Híbrido (Scanner Turbo de 100 threads + Tor Isolado)")
        print("4. Conexão Direta (Sem Proxy - apenas para testar a rota)")
        proxy_mode = input("Digite 1, 2, 3 ou 4 (Enter para 1): ").strip()
        if not proxy_mode:
            proxy_mode = "1"
        if proxy_mode in ["1", "2", "3", "4"]:
            break
        print("[ERRO] Escolha de 1 a 4.")

    if proxy_mode == "2" and not porta_local_aberta("127.0.0.1", 9050):
        print(
            "\n[AVISO] O serviço Tor (porta 9050) não está ativo! A mudar para o"
            " Modo 1 (Scanner Turbo)."
        )
        proxy_mode = "1"

    # --- 7. QUANTIDADE DE WORKERS SIMULTÂNEOS ---
    qtd_workers_input = input(
        "\nQuantos workers simultâneos deseja rodar? (Enter para 5): "
    ).strip()
    NUM_WORKERS = (
        int(qtd_workers_input)
        if (qtd_workers_input.isdigit() and int(qtd_workers_input) > 0)
        else 5
    )

    if proxy_mode in ("1", "3"):
        print(
            "\n[SCANNER TURBO] A recolher milhares de proxies e a iniciar 100"
            f" threads de teste contra {origin_url}..."
        )
        abastecer_candidatos_ineditos()
        t_scanner = threading.Thread(
            target=mantenedor_turbo_ips, args=(origin_url,), daemon=True
        )
        t_scanner.start()

        print("[SCANNER TURBO] A aguardar os primeiros IPs limpos responderem...")
        while fila_ips_prontos.empty() and not parar_execucao.is_set():
            time.sleep(0.2)
        print(
            f"[PRONTO] Fila abastecida ({fila_ips_prontos.qsize()} IPs limpos). A"
            " iniciar disparos na API!"
        )

    threads = []
    for i in range(1, NUM_WORKERS + 1):
        t = threading.Thread(
            target=worker_automacao_api,
            args=(
                i,
                api_url,
                origin_url,
                host_domain,
                password,
                email_choice,
                email_user_fixed,
                user_prefix,
                proxy_mode,
            ),
            daemon=True,
        )
        threads.append(t)
        t.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\n[INTERRUPÇÃO] A encerrar workers e scanner...")
        parar_execucao.set()
        for t in threads:
            t.join(timeout=2)
        print(
            "[STATUS FINAL] Total de contas criadas com sucesso (201 Created):"
            f" {accounts_created_sucessfully}"
        )
        print(
            "[INFO] Total de IPs inéditos varridos pelo scanner:"
            f" {len(ips_ja_usados_ou_testados)}"
        )
        print(
            f"[INFO] Último número de utilizador processado: {current_attempt - 1}"
        )