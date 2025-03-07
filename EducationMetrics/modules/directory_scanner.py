"""
Módulo de Descoberta de Diretórios
Responsável por realizar varredura controlada em busca de diretórios
e arquivos no servidor alvo.

Características:
- Implementa controle de taxa de requisições
- Usa lista de palavras comum para testes
- Realiza verificações de forma segura e não-intrusiva
"""

import requests
import logging
from urllib.parse import urljoin
import time

logger = logging.getLogger(__name__)

# Lista padrão de diretórios comuns para verificação
# Esta lista inclui caminhos frequentemente encontrados em aplicações web
DEFAULT_WORDLIST = [
    # Áreas administrativas
    'admin', 'wp-admin', 'administrator', 'login',

    # Diretórios de conteúdo
    'wp-content', 'upload', 'uploads', 

    # Backups e configurações
    'backup', 'backups', 'config',

    # Áreas de desenvolvimento
    'dashboard', 'cms', 'test', 'dev', 'desenvolvimento',

    # Ambientes e APIs
    'staging', 'prod', 'api', 'v1', 'v2',

    # Arquivos comuns
    'phpinfo', 'php', 'index', 'images', 'img'
]

def discover_directories(base_url, wordlist=None, delay=1):
    """
    Descobre diretórios e arquivos usando uma lista de palavras
    Implementa limitação de taxa para evitar sobrecarga do servidor

    Processo de descoberta:
    1. Itera sobre a lista de palavras
    2. Testa cada caminho possível
    3. Registra respostas relevantes
    4. Implementa delays entre requisições

    Parâmetros:
    - base_url: URL base para varredura
    - wordlist: Lista personalizada de palavras (opcional)
    - delay: Atraso entre requisições em segundos (padrão: 1s)

    Retorna:
    - Dicionário com diretórios descobertos e erros encontrados
    """
    # Inicializa estrutura para armazenar resultados
    results = {
        'discovered': [],    # Lista de diretórios/arquivos encontrados
        'errors': []        # Erros encontrados durante a varredura
    }

    # Usa a wordlist fornecida ou a padrão
    wordlist = wordlist or DEFAULT_WORDLIST

    try:
        # Itera sobre cada palavra da lista
        for word in wordlist:
            # Adiciona atraso entre requisições para evitar sobrecarga
            # e possível detecção como ataque
            time.sleep(delay)

            # Monta a URL completa para teste
            test_url = urljoin(base_url, word)
            try:
                # Faz requisição HEAD (mais leve que GET)
                response = requests.head(
                    test_url,
                    timeout=5,            # Timeout para evitar esperas longas
                    allow_redirects=True, # Segue redirecionamentos
                    verify=True           # Verifica certificados SSL
                )

                # Verifica códigos de status relevantes:
                # 200 = Encontrado
                # 301/302 = Redirecionamento
                # 403 = Acesso Proibido (mas existe)
                if response.status_code in [200, 301, 302, 403]:
                    results['discovered'].append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', 'desconhecido')
                    })

            except requests.exceptions.RequestException as e:
                # Registra erros para análise posterior
                results['errors'].append({
                    'url': test_url,
                    'error': str(e)
                })
                continue

    except Exception as e:
        logger.error(f"Falha na descoberta de diretórios: {str(e)}")
        raise Exception(f"Falha na descoberta de diretórios: {str(e)}")

    return results