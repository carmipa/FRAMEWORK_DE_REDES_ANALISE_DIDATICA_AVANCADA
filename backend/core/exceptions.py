"""Hierarquia de exceções customizadas do backend.

Regra de uso:
- `EntradaInvalidaError`: erro causado por entrada do usuário (HTTP 400).
- `InfraestruturaError` e subclasses: erro interno/dependência (HTTP 500).
"""


class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário.

    Use quando:
    - campo obrigatório estiver ausente/vazio;
    - formato de dado estiver inválido (IP/CIDR/domínio etc.);
    - valor estiver fora do intervalo esperado.
    """


class InfraestruturaError(RuntimeError):
    """Erro de infraestrutura/serviço interno.

    Use quando algo que deveria funcionar falha por motivos internos:
    indisponibilidade de serviço, timeout inesperado, erro de IO etc.
    """


class DnsResolucaoError(InfraestruturaError):
    """Falha geral ao resolver DNS.

    Exemplo: domínio inexistente, falha de resolução ou rede indisponível.
    """


class DnsResolucaoTimeoutError(DnsResolucaoError):
    """Timeout durante resolução DNS.

    Subclasse específica para cenários onde um retry/fallback pode ajudar.
    """


class HistoricoPersistenciaError(InfraestruturaError):
    """Falha ao carregar/persistir histórico local.

    Exemplo: arquivo corrompido, permissão insuficiente ou erro de escrita.
    """
