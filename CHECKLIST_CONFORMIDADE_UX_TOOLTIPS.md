# Checklist de Conformidade UX - Tooltips e Hover

## Objetivo

Garantir que campos de texto, seletores e botões tenham explicação clara ao passar o mouse, mantendo consistência didática e reduzindo dúvidas de uso.

---

## Regra padrão do projeto

Todo elemento interativo de formulário/ação deve ter ajuda contextual:

- `input`, `select`, `textarea`: tooltip no próprio campo;
- botões de ação (`button`, `.btn`, navegação de paginação): tooltip no botão;
- ícones de ajuda (`help-hint-btn`): popover com explicação curta e direta.

Padrão recomendado:

```html
data-bs-toggle="tooltip"
data-bs-placement="top"
title="Explicação objetiva da ação/campo."
```

---

## Checklist rápido (antes de fechar uma entrega)

- [ ] Campos de entrada (`input`) com `title` explicando formato esperado.
- [ ] Seletores (`select`) com `title` explicando impacto do filtro/valor.
- [ ] Botões primários (ex.: Executar, Exportar) com tooltip funcional.
- [ ] Botões secundários (ex.: Limpar, Detalhes, Copiar) com tooltip funcional.
- [ ] Botões de paginação (`⬅️` e `➡️`) com tooltip de navegação.
- [ ] Botões de modal (fechar/ações internas) com tooltip quando aplicável.
- [ ] Conteúdo do tooltip em linguagem simples e didática.
- [ ] Nenhum tooltip descrevendo "o que já está óbvio"; foco em intenção/efeito.

---

## Checklist técnico (implementação)

- [ ] Elemento possui `data-bs-toggle="tooltip"`.
- [ ] Elemento possui `title="..."`.
- [ ] Quando necessário, possui `data-bs-placement` (`top` como padrão).
- [ ] Inicialização global de tooltips está ativa no template principal.
- [ ] Tooltips novos foram validados em desktop (hover) e foco por teclado.

---

## Cobertura atual (referência)

Áreas revisadas no ciclo atual:

- `templates/partials/tab_protocolos.html`
- `templates/partials/tab_portas.html`
- `templates/partials/tab_cidr.html`
- `templates/partials/tab_mask.html`
- `templates/partials/tab_wildcard.html`
- `templates/partials/tab_autoip.html`
- `templates/partials/tab_dominio.html`
- `templates/partials/tab_comparador.html`
- `templates/partials/tab_geo.html`
- `templates/index.html`

---

## Critérios de aceitação UX

Um item está conforme quando:

1. Usuário entende o que o elemento faz sem consultar código.
2. Tooltip não conflita com o texto visível do componente.
3. Mensagem é curta (1 frase), orientada a ação.
4. O comportamento está consistente entre abas e componentes equivalentes.

---

## Boas práticas de escrita para tooltips

- Comece com verbo de ação: "Executa...", "Filtra...", "Copia...".
- Explique efeito, não implementação interna.
- Evite jargão sem contexto.
- Mantenha frases entre 8 e 18 palavras.
- Em casos didáticos, inclua exemplo curto quando necessário.

---

## Fluxo recomendado de validação

1. Verificar visualmente cada aba e botões de ação.
2. Passar o mouse nos elementos interativos críticos.
3. Navegar por teclado (TAB) para validar foco e dica.
4. Rodar testes/lint após ajustes de template.
5. Registrar mudanças de UX no histórico do PR.
