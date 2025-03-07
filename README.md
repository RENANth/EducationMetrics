
# Scanner de Segurança Web

Um scanner de segurança web modular que realiza análises não-intrusivas para identificar potenciais vulnerabilidades em aplicações web.

## Visão Geral

Esta ferramenta foi projetada para realizar análises passivas de segurança em aplicações web, ajudando desenvolvedores e profissionais de segurança a identificar possíveis vulnerabilidades antes que possam ser exploradas por atacantes.

## Características

- **Reconhecimento (Recon)**: Coleta de cabeçalhos HTTP, identificação de tecnologias e informações de DNS
- **Análise de Vulnerabilidades**: Detecção de pontos potenciais de XSS, SQL Injection e divulgação de informações
- **Descoberta de Diretórios**: Varredura controlada para identificar diretórios e arquivos sensíveis
- **Interface Web**: Interface amigável para configuração e visualização de resultados
- **Taxa Limitada**: Implementação de limitação de taxa para evitar sobrecarga do servidor alvo

## Tecnologias Utilizadas

- Python 3.11
- Flask (Framework Web)
- BeautifulSoup4 (Análise HTML)
- Requests (Requisições HTTP)
- DNS Python (Consultas DNS)
- Bootstrap (UI/UX)

## Estrutura do Projeto

```
├── modules/                 # Módulos funcionais do scanner
│   ├── directory_scanner.py # Descoberta de diretórios
│   ├── recon.py             # Reconhecimento inicial
│   ├── scanner.py           # Análise de vulnerabilidades
│   └── utils.py             # Funções auxiliares
├── static/                  # Arquivos estáticos (CSS, JS)
├── templates/               # Templates HTML
│   ├── index.html           # Página inicial
│   └── scan_results.html    # Página de resultados
├── app.py                   # Aplicação Flask principal
└── main.py                  # Ponto de entrada da aplicação
```

## Como Usar

1. Execute a aplicação:
   ```
   python main.py
   ```
   ou
   ```
   gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
   ```

2. Acesse a interface web em http://localhost:5000

3. Insira a URL do alvo que deseja analisar

4. Analise os resultados apresentados nas seguintes categorias:
   - Informações de reconhecimento (headers, tecnologias, DNS)
   - Vulnerabilidades potenciais (XSS, SQL Injection, etc.)
   - Diretórios e arquivos descobertos

## Considerações de Segurança

- Esta ferramenta foi projetada para testes éticos e deve ser usada apenas em sites que você tem permissão para testar
- O scanner implementa limites de taxa para evitar sobrecarga dos servidores alvo
- Todas as verificações são realizadas de forma não-intrusiva e passiva

## Limitações

- O scanner realiza apenas testes passivos e não-intrusivos
- Falsos positivos podem ocorrer e devem ser verificados manualmente
- A ferramenta não explora vulnerabilidades, apenas as identifica

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias.

## Licença

Este projeto é licenciado sob a licença MIT.
