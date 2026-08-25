# -*- coding: utf-8 -*-
"""Чтение и запись config.ini.

Файл — единственный источник настроек: его читают и GUI (main.py),
и запуск из консоли (python p7b.py). Править можно руками.
"""
import configparser
import os

import p7b

CONFIG_FILE = 'config.ini'

ALL_CERTIFICATES = 'all'
USER_CERTIFICATES = 'user'


def _header():
    presets = ' | '.join(p7b.PRESETS)
    fields = '\n'.join(
        '#   {{{0}}}{1}— {2}'.format(key, ' ' * max(1, 14 - len(key)), label)
        for key, (label, _example) in p7b.FIELDS.items())
    return (
        "# Настройки извлечения сертификатов из .p7b.\n"
        "# Файл читают и GUI, и запуск из консоли (python p7b.py).\n"
        "# GUI перезаписывает его при изменении настроек.\n"
        "#\n"
        "# Naming.Preset — готовый вариант имени файла, одно из:\n"
        "#   {presets}\n"
        "# Naming.Template используется, когда Preset = custom.\n"
        "# Поля, доступные в шаблоне:\n"
        "{fields}\n"
        "#\n"
        "# Extract.Certificates:\n"
        "#   all  — извлекать все сертификаты, включая вышестоящие (УЦ)\n"
        "#   user — только сертификаты пользователя\n"
        "# Extract.AttributeCertificates:\n"
        "#   no  — атрибутные сертификаты (AttributeCertificate) пропускаются\n"
        "#   yes — извлекать и их тоже, в файлы .acr\n"
        "#\n"
        "# General.ShowGui:\n"
        "#   yes — при запуске открывается окно программы\n"
        "#   no  — окно не открывается, извлечение стартует сразу\n"
        "#         и программа закрывается (результат — в файле log_*.txt)\n"
        "# Открыть окно при ShowGui = no: запустить с ключом --gui\n"
        "# Разово запустить без окна при ShowGui = yes: ключ --no-gui\n"
        "\n".format(presets=presets, fields=fields))


class Settings:
    def __init__(self, path=CONFIG_FILE):
        self.path = path
        self.input_folder = ''
        self.output_folder = ''
        self.preset = p7b.DEFAULT_PRESET
        self.custom_template = p7b.DEFAULT_TEMPLATE
        self.only_user_certs = False
        self.extract_attribute_certs = False
        self.show_gui = True

    def load(self):
        if not os.path.exists(self.path):
            return self

        parser = configparser.ConfigParser()
        try:
            parser.read(self.path, encoding='utf-8')
        except (configparser.Error, UnicodeDecodeError):
            return self

        self.input_folder = parser.get('Paths', 'InputFolder', fallback='').strip()
        self.output_folder = parser.get('Paths', 'OutputFolder', fallback='').strip()

        preset = parser.get('Naming', 'Preset', fallback=p7b.DEFAULT_PRESET).strip()
        self.preset = preset if preset in p7b.PRESETS else p7b.DEFAULT_PRESET
        self.custom_template = parser.get(
            'Naming', 'Template', fallback=p7b.DEFAULT_TEMPLATE).strip() or p7b.DEFAULT_TEMPLATE

        certificates = parser.get('Extract', 'Certificates', fallback=ALL_CERTIFICATES).strip().lower()
        self.only_user_certs = certificates == USER_CERTIFICATES

        try:
            self.extract_attribute_certs = parser.getboolean(
                'Extract', 'AttributeCertificates', fallback=False)
        except ValueError:
            self.extract_attribute_certs = False

        try:
            self.show_gui = parser.getboolean('General', 'ShowGui', fallback=True)
        except ValueError:
            self.show_gui = True

        # Значения 'None' остались от прежних версий, когда путь не был выбран.
        for attribute in ('input_folder', 'output_folder'):
            if getattr(self, attribute) == 'None':
                setattr(self, attribute, '')

        return self

    def save(self):
        content = _header() + (
            "[Paths]\n"
            "InputFolder = {input_folder}\n"
            "OutputFolder = {output_folder}\n"
            "\n"
            "[Naming]\n"
            "Preset = {preset}\n"
            "Template = {template}\n"
            "\n"
            "[Extract]\n"
            "Certificates = {certificates}\n"
            "AttributeCertificates = {attribute_certificates}\n"
            "\n"
            "[General]\n"
            "ShowGui = {show_gui}\n"
        ).format(
            input_folder=self.input_folder or '',
            output_folder=self.output_folder or '',
            preset=self.preset,
            template=self.custom_template,
            certificates=USER_CERTIFICATES if self.only_user_certs else ALL_CERTIFICATES,
            attribute_certificates='yes' if self.extract_attribute_certs else 'no',
            show_gui='yes' if self.show_gui else 'no',
        )
        with open(self.path, 'w', encoding='utf-8') as config_file:
            config_file.write(content)
        return self

    def template(self):
        """Шаблон имени файла с учётом выбранного пресета."""
        return p7b.template_for_preset(self.preset, self.custom_template)
