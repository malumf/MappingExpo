# Google Dork Generator I.C.W.T 2026
# MappingExpo Project
import yaml
import itertools
import re
import random
from pathlib import Path


MODE_HIERARCHY = {
    "soft":       ["soft"],
    "medium":     ["soft", "medium"],
    "aggressive": ["soft", "medium", "aggressive"]
}


class DorkGenerator:

    def __init__(self, yaml_file: str, max_combinations: int = 10000):
        self.yaml_file = Path(yaml_file)
        self.max_combinations = max_combinations
        self.variables = {}
        self.templates = {}
        self._load()

    # ─────────────────────────────────────────────
    # CARREGAMENTO DE TEMPLATES
    # ─────────────────────────────────────────────

    def _load(self):
        if not self.yaml_file.exists():
            raise FileNotFoundError(f"Arquivo de template não encontrado: {self.yaml_file}")

        with open(self.yaml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Estrutura YAML inválida em: {self.yaml_file}")

        self.variables = data.get("variables", {})
        self.templates = data.get("templates", {})

    # ─────────────────────────────────────────────
    # UTILITÁRIOS DE PLACEHOLDER
    # ─────────────────────────────────────────────

    def _extract_placeholders(self, template: str) -> list:
        """Extrai os placeholders preservando a ordem, sem duplicatas."""
        seen = set()
        unique = []
        for ph in re.findall(r"\{(.*?)\}", template):
            if ph not in seen:
                seen.add(ph)
                unique.append(ph)
        return unique

    def _validate_placeholders(self, template: str, category: str):
        """Emite um aviso se um placeholder não estiver definido nas variáveis."""
        placeholders = re.findall(r"\{(.*?)\}", template)
        unknown = [ph for ph in placeholders if ph not in self.variables]
        if unknown:
            print(
                f"[AVISO] Categoria '{category}': "
                f"placeholder(s) desconhecido(s) {unknown} em: {template}"
            )

    # ─────────────────────────────────────────────
    # GERAÇÃO
    # ─────────────────────────────────────────────

    def _generate_from_template(self, template: str) -> list:
        """
        Gera todas as combinações para um único template.
        A amostragem ocorre ANTES da expansão para evitar
        explosões de memória em templates com muitas variáveis.
        """
        placeholders = self._extract_placeholders(template)

        if not placeholders:
            return [template]

        value_lists = []
        for ph in placeholders:
            values = self.variables.get(ph)
            if not values:
                values = [f"{{{ph}}}"]
            value_lists.append(values)

        # Estima o total de combinações sem gerá-las todas
        total = 1
        for vl in value_lists:
            total *= len(vl)

        # Faz amostragem antes de expandir se ultrapassar o limite
        if total > self.max_combinations:
            sampled = set()
            attempts = 0
            max_attempts = self.max_combinations * 3

            while len(sampled) < self.max_combinations and attempts < max_attempts:
                combo = tuple(random.choice(vl) for vl in value_lists)
                sampled.add(combo)
                attempts += 1

            combinations = list(sampled)
        else:
            combinations = list(itertools.product(*value_lists))

        generated = []
        for combo in combinations:
            result = template
            for ph, value in zip(placeholders, combo):
                result = result.replace(f"{{{ph}}}", str(value))
            generated.append(result)

        return generated

    def _get_dork_list(self, data: dict, allowed_modes: list) -> list:
        """
        Extrai os dorks de uma categoria suportando duas estruturas YAML:

        Estrutura A — aninhada (recomendada):
            dorks:
              soft:
                - 'dork1'
              medium:
                - 'dork2'
              aggressive:
                - 'dork3'

        Estrutura B — plana com modo único (legado):
            mode: soft
            dorks:
              - 'dork1'
              - 'dork2'
        """
        raw_dorks = data.get("dorks", [])

        # ── Estrutura A: dorks é um dict com as chaves soft/medium/aggressive ──
        if isinstance(raw_dorks, dict):
            collected = []
            for level, dork_list in raw_dorks.items():
                # Inclui apenas os níveis permitidos pela hierarquia
                if allowed_modes is None or level in allowed_modes:
                    if isinstance(dork_list, list):
                        collected.extend(dork_list)
            return collected

        # ── Estrutura B: dorks é uma lista plana, o mode fica no nível da categoria ──
        if isinstance(raw_dorks, list):
            template_mode = data.get("mode", "soft")
            if allowed_modes is None or template_mode in allowed_modes:
                return raw_dorks
            return []

        return []

    def generate(self, categories: list = None, mode: str = None) -> list:
        """
        Gera dorks filtrados por categoria e modo.

        Hierarquia de modos:
          soft       → apenas templates "soft"
          medium     → "soft" + "medium"
          aggressive → "soft" + "medium" + "aggressive"
          None       → sem filtro, todos os templates
        """
        all_dorks = []

        selected_templates = self.templates

        if categories:
            selected_templates = {
                k: v for k, v in self.templates.items() if k in categories
            }

        # Calcula os modos permitidos com base na hierarquia
        allowed_modes = MODE_HIERARCHY.get(mode) if mode else None

        for category, data in selected_templates.items():
            dork_templates = self._get_dork_list(data, allowed_modes)

            for template in dork_templates:
                # Valida os placeholders antes de gerar
                self._validate_placeholders(template, category)
                generated = self._generate_from_template(template)
                all_dorks.extend(generated)

        # Deduplicação global + embaralhamento
        all_dorks = list(set(all_dorks))
        random.shuffle(all_dorks)

        # Limite global de segurança
        if len(all_dorks) > self.max_combinations:
            all_dorks = all_dorks[:self.max_combinations]

        return all_dorks

    # ─────────────────────────────────────────────
    # INTROSPECÇÃO
    # ─────────────────────────────────────────────

    def get_available_categories(self) -> list:
        """Retorna as categorias disponíveis no template carregado."""
        return sorted(self.templates.keys())

    def get_available_modes(self) -> list:
        """
        Retorna os modos disponíveis detectando automaticamente tanto
        estruturas aninhadas quanto planas.
        """
        modes = set()
        for data in self.templates.values():
            raw_dorks = data.get("dorks", [])
            if isinstance(raw_dorks, dict):
                modes.update(raw_dorks.keys())
            else:
                modes.add(data.get("mode", "soft"))
        return sorted(modes)

    def get_stats(self) -> dict:
        """Estatísticas úteis para depuração e relatórios."""
        total = 0
        for data in self.templates.values():
            raw_dorks = data.get("dorks", [])
            if isinstance(raw_dorks, dict):
                for dlist in raw_dorks.values():
                    if isinstance(dlist, list):
                        total += len(dlist)
            elif isinstance(raw_dorks, list):
                total += len(raw_dorks)

        return {
            "yaml_file":        str(self.yaml_file),
            "categories":       self.get_available_categories(),
            "available_modes":  self.get_available_modes(),
            "total_templates":  total,
            "variables": {
                k: len(v) for k, v in self.variables.items()
            }
        }
