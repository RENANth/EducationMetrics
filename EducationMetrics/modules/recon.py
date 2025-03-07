"""
Módulo de Reconhecimento (Recon)
Este módulo é responsável pela coleta inicial de informações sobre o alvo.
Realiza análises passivas para identificar tecnologias e configurações.

Funcionalidades:
- Coleta de cabeçalhos HTTP
- Identificação de tecnologias utilizadas
- Análise de DNS
- Coleta de informações do servidor
"""

import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import dns.resolver

logger = logging.getLogger(__name__)

def perform_recon(url):
    """
    Realiza reconhecimento básico no URL alvo

    O reconhecimento é feito em várias etapas:
    1. Coleta de cabeçalhos HTTP para identificar servidor e tecnologias
    2. Análise do HTML para detectar frameworks e bibliotecas
    3. Consultas DNS para obter informações de infraestrutura

    Parâmetros:
    - url: URL do alvo a ser analisado

    Retorna:
    - Dicionário com informações coletadas sobre o alvo:
      - Cabeçalhos HTTP
      - Tecnologias detectadas
      - Informações DNS
      - Informações do servidor
    """
    # Inicializa o dicionário que armazenará todos os resultados
    results = {
        'headers': {},          # Armazena cabeçalhos HTTP
        'technologies': [],     # Lista de tecnologias identificadas
        'dns_info': {},        # Informações de DNS
        'server_info': {}      # Informações do servidor
    }

    try:
        # Etapa 1: Coleta de cabeçalhos HTTP
        # Faz uma requisição GET e armazena os cabeçalhos da resposta
        response = requests.get(url, timeout=10, verify=True)
        results['headers'] = dict(response.headers)

        # Etapa 2: Identificação de tecnologias
        # Analisa o HTML em busca de indicadores de tecnologias
        soup = BeautifulSoup(response.text, 'html.parser')

        # Verifica meta tags que podem indicar o gerador do site
        if soup.find(attrs={"name": "generator"}):
            results['technologies'].append(soup.find(attrs={"name": "generator"})['content'])

        # Procura por frameworks comuns nos scripts carregados
        common_frameworks = ['react', 'angular', 'vue', 'jquery', 'bootstrap']
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            for framework in common_frameworks:
                if framework in src.lower():
                    results['technologies'].append(framework)

        # Etapa 3: Análise de DNS
        # Obtém informações sobre a infraestrutura do alvo
        domain = urlparse(url).netloc
        try:
            # Resolução de IP - Converte o domínio em endereço IP
            ip = socket.gethostbyname(domain)
            results['dns_info']['ip'] = ip

            # DNS reverso - Tenta obter o hostname a partir do IP
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                results['dns_info']['hostname'] = hostname
            except socket.herror:
                results['dns_info']['hostname'] = 'Não disponível'

            # Coleta diferentes tipos de registros DNS
            for record_type in ['A', 'MX', 'NS']:  # A=endereço, MX=mail, NS=nameserver
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results['dns_info'][record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    results['dns_info'][record_type] = []

        except socket.gaierror:
            results['dns_info']['error'] = 'Falha na resolução DNS'

    except requests.exceptions.RequestException as e:
        # Log de erro e propagação da exceção para tratamento adequado
        logger.error(f"Falha no reconhecimento: {str(e)}")
        raise Exception(f"Falha no reconhecimento: {str(e)}")

    return results