"""
Arquivo principal da aplicação de Scanner de Segurança Web
Este módulo implementa as rotas principais e coordena os diferentes
módulos de análise de segurança.

Funcionalidades principais:
- Página inicial com formulário de scan
- Execução do scan de segurança
- Exibição dos resultados
"""

import os
import logging
from flask import Flask, render_template, request, jsonify
from modules.recon import perform_recon
from modules.scanner import scan_vulnerabilities
from modules.directory_scanner import discover_directories
from modules.utils import validate_url, RateLimiter

# Configuração de logging para facilitar a depuração
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Inicialização da aplicação Flask
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Inicializa limitador de taxa - 10 requisições por minuto
# Este limitador ajuda a prevenir sobrecarga do servidor alvo
# e possível detecção como ataque DoS
rate_limiter = RateLimiter(10, 60)  # 10 requests a cada 60 segundos

@app.route('/')
def index():
    """
    Rota principal que renderiza a página inicial
    Retorna o template com o formulário de scan
    """
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """
    Rota que executa o scan de segurança

    Fluxo de execução:
    1. Valida a taxa de requisições
    2. Valida a URL fornecida
    3. Executa reconhecimento inicial
    4. Analisa vulnerabilidades
    5. Descobre diretórios
    6. Retorna resultados formatados

    Retorna:
    - Página de resultados em caso de sucesso
    - Mensagem de erro em caso de falha
    """
    # Verifica se o usuário não excedeu o limite de requisições
    if not rate_limiter.allow_request():
        return jsonify({
            'error': 'Limite de requisições excedido. Por favor, aguarde antes de fazer outra solicitação.'
        }), 429

    # Obtém e valida a URL fornecida pelo usuário
    target_url = request.form.get('target_url')
    if not validate_url(target_url):
        return jsonify({'error': 'URL inválida fornecida'}), 400

    try:
        # Passo 1: Executa reconhecimento inicial
        # Coleta informações básicas sobre o alvo (cabeçalhos, tecnologias, DNS)
        recon_results = perform_recon(target_url)

        # Passo 2: Analisa vulnerabilidades
        # Procura por possíveis falhas de segurança como XSS, SQLi, etc
        vuln_results = scan_vulnerabilities(target_url)

        # Passo 3: Descobre diretórios
        # Tenta encontrar diretórios e arquivos ocultos ou sensíveis
        dir_results = discover_directories(target_url)

        # Consolida todos os resultados em um dicionário
        results = {
            'recon': recon_results,
            'vulnerabilities': vuln_results,
            'directories': dir_results
        }

        # Renderiza o template com os resultados
        return render_template('scan_results.html', results=results, target_url=target_url)

    except Exception as e:
        # Log detalhado do erro para depuração
        logger.error(f"Erro durante o scan: {str(e)}")
        return jsonify({'error': f'Falha no scan: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)