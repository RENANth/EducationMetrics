"""
Módulo de Análise de Vulnerabilidades
Este módulo implementa a detecção básica de vulnerabilidades web comuns.
Realiza testes não-intrusivos para identificar possíveis pontos fracos.

Funcionalidades:
- Detecção de potenciais pontos de XSS
- Identificação de possíveis pontos de injeção SQL
- Verificação de arquivos sensíveis expostos
- Análise de formulários e parâmetros
"""

import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger(__name__)

def scan_vulnerabilities(url):
    """
    Analisa vulnerabilidades comuns em aplicações web
    Realiza verificações passivas e de baixo impacto

    Processo de análise:
    1. Verifica formulários para potenciais XSS
    2. Analisa parâmetros de URL para possível SQLi
    3. Procura por arquivos sensíveis expostos

    Parâmetros:
    - url: URL do alvo a ser analisado

    Retorna:
    - Dicionário com vulnerabilidades encontradas:
      - XSS (Cross-Site Scripting)
      - Injeção SQL
      - Redirecionamentos abertos
      - Divulgação de informações
    """
    # Inicializa o dicionário para armazenar os resultados
    results = {
        'xss': [],              # Pontos potenciais de Cross-Site Scripting
        'sql_injection': [],    # Possíveis pontos de injeção SQL
        'open_redirects': [],   # Redirecionamentos não validados
        'information_disclosure': []  # Informações sensíveis expostas
    }

    try:
        # Faz requisição inicial para obter o conteúdo da página
        response = requests.get(url, timeout=10, verify=True)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Etapa 1: Análise de Formulários
        # Busca todos os formulários na página
        forms = soup.find_all('form')
        for form in forms:
            # Verifica campos de entrada que podem ser vulneráveis a XSS
            inputs = form.find_all('input')
            for input_field in inputs:
                # Campos de texto são mais suscetíveis a XSS
                if input_field.get('type') in ['text', 'search', 'url', 'tel', 'email']:
                    results['xss'].append({
                        'form_action': form.get('action', ''),
                        'input_name': input_field.get('name', ''),
                        'risk': 'Possível ponto de XSS - Validar e sanitizar entrada'
                    })

        # Etapa 2: Análise de Parâmetros URL
        # Verifica parâmetros que podem ser vulneráveis a SQL Injection
        params = parse_qs(urlparse(url).query)
        for param in params:
            results['sql_injection'].append({
                'parameter': param,
                'risk': 'Possível ponto de injeção SQL - Validar e sanitizar entrada'
            })

        # Etapa 3: Verificação de Arquivos Sensíveis
        # Lista de arquivos comumente sensíveis para verificar
        common_sensitive_files = [
            'robots.txt',      # Pode revelar estrutura do site
            '.git/HEAD',       # Exposição de repositório git
            'wp-config.php',   # Configuração WordPress
            '.env',            # Arquivo de variáveis de ambiente
            'phpinfo.php'      # Informações do PHP
        ]

        # Testa cada arquivo sensível
        for file in common_sensitive_files:
            try:
                test_url = urljoin(url, file)
                response = requests.head(test_url, timeout=5)
                if response.status_code == 200:
                    results['information_disclosure'].append({
                        'file': file,
                        'risk': 'Arquivo potencialmente sensível exposto'
                    })
            except requests.exceptions.RequestException:
                continue

    except requests.exceptions.RequestException as e:
        logger.error(f"Falha na análise de vulnerabilidades: {str(e)}")
        raise Exception(f"Falha na análise de vulnerabilidades: {str(e)}")

    return results