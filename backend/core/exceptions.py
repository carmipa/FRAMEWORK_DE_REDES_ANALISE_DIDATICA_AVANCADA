class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário."""


class InfraestruturaError(RuntimeError):
    """Erro de infraestrutura/serviço interno."""


class DnsResolucaoError(InfraestruturaError):
    """Falha geral ao resolver DNS."""


class DnsResolucaoTimeoutError(DnsResolucaoError):
    """Timeout durante resolução DNS."""


class HistoricoPersistenciaError(InfraestruturaError):
    """Falha ao carregar/persistir histórico local."""
