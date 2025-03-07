"""
Módulo de Utilidades
Fornece funções auxiliares utilizadas pelos outros módulos do scanner.

Funcionalidades:
- Limitador de taxa de requisições
- Validação de URLs
- Sanitização de entrada
"""

import re
import time
from urllib.parse import urlparse

class RateLimiter:
    """
    Implementa controle de taxa de requisições
    Evita sobrecarga do servidor alvo e possível detecção como ataque

    Atributos:
    - max_requests: Número máximo de requisições permitidas
    - time_window: Janela de tempo em segundos
    - requests: Lista de timestamps das requisições
    """
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests    # Máximo de requisições permitidas
        self.time_window = time_window      # Período de tempo (segundos)
        self.requests = []                  # Histórico de requisições

    def allow_request(self):
        """
        Verifica se uma nova requisição pode ser feita

        Processo:
        1. Remove requisições antigas da janela de tempo
        2. Verifica se há espaço para nova requisição
        3. Registra nova requisição se permitida

        Retorna:
        - Boolean: True se requisição permitida, False caso contrário
        """
        current_time = time.time()

        # Remove requisições fora da janela de tempo
        self.requests = [req_time for req_time in self.requests 
                        if current_time - req_time < self.time_window]

        # Verifica se pode permitir nova requisição
        if len(self.requests) < self.max_requests:
            self.requests.append(current_time)
            return True

        return False

def validate_url(url):
    """
    Valida formato e esquema da URL fornecida

    Verificações:
    1. URL não pode ser vazia
    2. Deve ter esquema (http/https)
    3. Deve ter domínio válido

    Parâmetros:
    - url: String com a URL a ser validada

    Retorna:
    - Boolean: True se URL válida, False caso contrário
    """
    if not url:
        return False

    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def sanitize_input(input_string):
    """
    Sanitiza entrada do usuário para prevenir injeções
    Remove caracteres potencialmente perigosos

    Parâmetros:
    - input_string: String a ser sanitizada

    Retorna:
    - String sanitizada
    """
    # Remove caracteres não permitidos, mantendo apenas:
    # - Alfanuméricos
    # - Caracteres comuns em URLs
    return re.sub(r'[^a-zA-Z0-9\-\._~:/?#\[\]@!\$&\'\(\)\*\+,;=]', '', input_string)