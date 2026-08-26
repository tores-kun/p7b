# -*- coding: utf-8 -*-
import sys, os, logging
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
                             QFileDialog, QMessageBox, QLabel, QComboBox,
                             QLineEdit, QCheckBox, QMenu, QFormLayout)
from PyQt5.QtCore import Qt
from p7b import (parse_p7b_files, FIELDS, PRESETS, DATE_FORMATS, build_filename,
                 template_for_preset, date_format_for_preset,
                 example_fields, read_first_certificate_fields)
from settings import Settings
from datetime import datetime


class CertificateParserApp(QWidget):
    def __init__(self, settings=None):
        super().__init__()

        self.settings = settings if settings is not None else Settings().load()
        self.log_filename = None
        self.preview_fields = example_fields()
        self.init_ui()
        self.reload_preview_fields()

    # Настройки хранятся в config.ini, его же можно править вручную.
    @property
    def input_folder(self):
        return self.settings.input_folder

    @property
    def output_folder(self):
        return self.settings.output_folder

    def save_config(self):
        self.settings.save()

    def init_ui(self):
        self.setWindowTitle('Извлечение всех .cer из .p7b')
        self.resize(600, 330)
        self.setMinimumWidth(520)

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(8)

        # Папки: подпись слева, поле ввода (можно вписать путь вручную) + «Обзор…».
        folders_form = QFormLayout()
        folders_form.setSpacing(6)
        folders_form.setLabelAlignment(Qt.AlignLeft)

        input_row = QHBoxLayout()
        self.input_folder_edit = QLineEdit(self)
        self.input_folder_edit.setText(self.input_folder)
        self.input_folder_edit.setToolTip(self.input_folder)
        self.input_folder_edit.setPlaceholderText(r'C:\certs\in')
        self.input_folder_edit.textChanged.connect(self.on_input_folder_changed)
        input_row.addWidget(self.input_folder_edit)
        self.input_folder_button = QPushButton('Обзор…', self)
        self.input_folder_button.clicked.connect(self.select_input_folder)
        input_row.addWidget(self.input_folder_button)
        folders_form.addRow('Папка с .p7b:', input_row)

        output_row = QHBoxLayout()
        self.output_folder_edit = QLineEdit(self)
        self.output_folder_edit.setText(self.output_folder)
        self.output_folder_edit.setToolTip(self.output_folder)
        self.output_folder_edit.setPlaceholderText(r'C:\certs\out')
        self.output_folder_edit.textChanged.connect(self.on_output_folder_changed)
        output_row.addWidget(self.output_folder_edit)
        self.output_folder_button = QPushButton('Обзор…', self)
        self.output_folder_button.clicked.connect(self.select_output_folder)
        output_row.addWidget(self.output_folder_button)
        folders_form.addRow('Папка для .cer:', output_row)

        main_layout.addLayout(folders_form)
        main_layout.addLayout(self.build_naming_ui())
        main_layout.addStretch(1)

        self.run_button = QPushButton('Запустить', self)
        self.run_button.clicked.connect(self.run_parser)
        self.run_button.setObjectName('runButton')

        self.author_label = QLabel('© Белоусов А.В.', self)
        self.author_label.setObjectName('author')

        footer_layout = QHBoxLayout()
        footer_layout.addWidget(self.author_label, alignment=Qt.AlignLeft | Qt.AlignVCenter)
        footer_layout.addStretch()
        footer_layout.addWidget(self.run_button, alignment=Qt.AlignRight | Qt.AlignVCenter)
        main_layout.addLayout(footer_layout)

        # Применение стилей к виджетам через qss — единый блок вместо стиля на каждой кнопке.
        self.setStyleSheet("""
            CertificateParserApp {
                background-color: #f1f4f2;
            }
            QLabel {
                color: black;
                background-color: transparent;
                padding: 1px;
            }
            QLabel#preview {
                background-color: white;
                border: 1px solid #c9d4cd;
                border-radius: 5px;
                padding: 5px;
                font-style: italic;
            }
            QLabel#author {
                color: #8a938d;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: white;
                border: 1px solid #c9d4cd;
                border-radius: 4px;
                padding: 4px 6px;
            }
            QLineEdit:disabled, QComboBox:disabled {
                background-color: #eceeed;
                color: #9aa39d;
            }
            QLabel:disabled {
                color: #9aa39d;
            }
            QPushButton {
                color: white;
                background-color: #2e7d32;
                border: none;
                border-radius: 5px;
                padding: 5px 12px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #256428;
            }
            QPushButton:pressed {
                background-color: #1e501f;
            }
            QPushButton:disabled {
                background-color: #a9c2ab;
            }
            QPushButton#runButton {
                padding: 7px 22px;
                font-size: 14px;
                font-weight: bold;
            }
            QCheckBox {
                padding: 1px;
            }
        """)

    def build_naming_ui(self):
        """Блок выбора имени сертификата: пресет, свой шаблон, предпросмотр, флажки."""
        naming_container = QVBoxLayout()
        naming_container.setSpacing(6)

        naming_form = QFormLayout()
        naming_form.setSpacing(6)
        naming_form.setLabelAlignment(Qt.AlignLeft)

        self.preset_combo = QComboBox(self)
        for preset_key, (label, _template) in PRESETS.items():
            self.preset_combo.addItem(label, preset_key)
        self.preset_combo.setCurrentIndex(max(0, self.preset_combo.findData(self.settings.preset)))
        self.preset_combo.currentIndexChanged.connect(self.on_preset_changed)
        naming_form.addRow('Имя файла из:', self.preset_combo)

        template_row = QHBoxLayout()
        self.template_edit = QLineEdit(self)
        self.template_edit.setPlaceholderText('{CN}_{serial}')
        self.template_edit.textChanged.connect(self.on_template_changed)
        template_row.addWidget(self.template_edit)

        self.insert_field_button = QPushButton('+ поле', self)
        self.insert_field_button.setMenu(self.build_fields_menu())
        template_row.addWidget(self.insert_field_button)
        naming_form.addRow('Шаблон:', template_row)

        # Формат дат нужен, только если в шаблоне есть {valid_from}/{valid_to}.
        date_row = QHBoxLayout()
        self.date_format_combo = QComboBox(self)
        for key, (label, _fmt) in DATE_FORMATS.items():
            self.date_format_combo.addItem(label, key)
        self.date_format_combo.setCurrentIndex(
            max(0, self.date_format_combo.findData(self.settings.date_format_preset)))
        self.date_format_combo.currentIndexChanged.connect(self.on_date_format_preset_changed)
        date_row.addWidget(self.date_format_combo)

        self.date_format_edit = QLineEdit(self)
        self.date_format_edit.setPlaceholderText('%d.%m.%Y')
        self.date_format_edit.setToolTip(
            'Коды strftime: %Y — год (2026), %m — месяц (08), %d — день (21).\n'
            'Например: %Y — только год, %d.%m.%Y — 21.08.2026.')
        self.date_format_edit.textChanged.connect(self.on_date_format_changed)
        date_row.addWidget(self.date_format_edit)

        self.date_format_label = QLabel('Формат даты:', self)
        self.date_format_label.setToolTip(
            'Доступно, когда в шаблоне есть {valid_from} или {valid_to}.')
        naming_form.addRow(self.date_format_label, date_row)

        naming_container.addLayout(naming_form)

        self.preview_label = QLabel(self)
        self.preview_label.setObjectName('preview')
        self.preview_label.setWordWrap(True)
        naming_container.addWidget(self.preview_label)

        checks_layout = QVBoxLayout()
        checks_layout.setSpacing(2)
        checks_layout.setContentsMargins(0, 4, 0, 0)

        self.only_user_certs_checkbox = QCheckBox('Только сертификаты пользователя (без вышестоящих УЦ)', self)
        self.only_user_certs_checkbox.setChecked(self.settings.only_user_certs)
        self.only_user_certs_checkbox.stateChanged.connect(self.on_only_user_certs_changed)
        checks_layout.addWidget(self.only_user_certs_checkbox)

        self.extract_attribute_certs_checkbox = QCheckBox('Извлекать атрибутные сертификаты', self)
        self.extract_attribute_certs_checkbox.setChecked(self.settings.extract_attribute_certs)
        self.extract_attribute_certs_checkbox.setToolTip(
            'AttributeCertificate из .p7b (обычно СОК ЮЛ, совмещённый с атрибутным сертификатом).\n'
            'Сохраняются отдельно, с расширением .acr.')
        self.extract_attribute_certs_checkbox.stateChanged.connect(self.on_extract_attribute_certs_changed)
        checks_layout.addWidget(self.extract_attribute_certs_checkbox)

        self.headless_checkbox = QCheckBox('Запускать без окна — сразу извлекать и закрываться', self)
        self.headless_checkbox.setChecked(not self.settings.show_gui)
        self.headless_checkbox.setToolTip('Чтобы снова открыть это окно, запустите программу с ключом --gui')
        self.headless_checkbox.stateChanged.connect(self.on_headless_changed)
        checks_layout.addWidget(self.headless_checkbox)

        naming_container.addLayout(checks_layout)

        self.apply_preset_to_template_edit()
        self.apply_date_format_preset_to_edit()
        return naming_container

    def build_fields_menu(self):
        menu = QMenu(self)
        for field_key, (label, _example) in FIELDS.items():
            action = menu.addAction(f'{label}  —  {{{field_key}}}')
            action.triggered.connect(lambda _checked, key=field_key: self.insert_field(key))
        return menu

    def insert_field(self, field_key):
        if not self.template_edit.isEnabled():
            return
        self.template_edit.insert('{%s}' % field_key)
        self.template_edit.setFocus()

    def current_preset(self):
        return self.preset_combo.currentData()

    def apply_preset_to_template_edit(self):
        """Для готового пресета показываем его шаблон только для чтения."""
        preset = self.current_preset()
        is_custom = preset == 'custom'
        self.template_edit.setEnabled(is_custom)
        self.insert_field_button.setEnabled(is_custom)

        self.template_edit.blockSignals(True)
        self.template_edit.setText(template_for_preset(preset, self.settings.custom_template))
        self.template_edit.blockSignals(False)
        self.update_date_format_availability()
        self.update_preview()

    def on_preset_changed(self):
        self.settings.preset = self.current_preset()
        self.apply_preset_to_template_edit()
        self.save_config()

    def on_template_changed(self, text):
        if self.current_preset() == 'custom':
            self.settings.custom_template = text
            self.save_config()
        self.update_date_format_availability()
        self.update_preview()

    def current_date_format_preset(self):
        return self.date_format_combo.currentData()

    def template_uses_dates(self):
        """В шаблоне есть поле с датой — только тогда её формат на что-то влияет."""
        template = self.current_template()
        return '{valid_from}' in template or '{valid_to}' in template

    def update_date_format_availability(self):
        """Настройки формата даты доступны, только если шаблон содержит дату."""
        uses_dates = self.template_uses_dates()
        self.date_format_label.setEnabled(uses_dates)
        self.date_format_combo.setEnabled(uses_dates)
        self.date_format_edit.setEnabled(
            uses_dates and self.current_date_format_preset() == 'custom')

    def apply_date_format_preset_to_edit(self):
        """Для готового формата даты показываем его строку только для чтения."""
        preset = self.current_date_format_preset()

        self.date_format_edit.blockSignals(True)
        self.date_format_edit.setText(
            date_format_for_preset(preset, self.settings.custom_date_format))
        self.date_format_edit.blockSignals(False)
        self.update_date_format_availability()
        self.reload_preview_fields()

    def on_date_format_preset_changed(self):
        self.settings.date_format_preset = self.current_date_format_preset()
        self.apply_date_format_preset_to_edit()
        self.save_config()

    def on_date_format_changed(self, text):
        if self.current_date_format_preset() == 'custom':
            self.settings.custom_date_format = text
            self.save_config()
        self.reload_preview_fields()

    def on_only_user_certs_changed(self, state):
        self.settings.only_user_certs = bool(state)
        self.save_config()

    def on_extract_attribute_certs_changed(self, state):
        self.settings.extract_attribute_certs = bool(state)
        self.save_config()

    def on_headless_changed(self, state):
        self.settings.show_gui = not state
        self.save_config()
        if state:
            QMessageBox.information(
                self, 'Запуск без окна',
                'При следующих запусках окно открываться не будет: программа сразу '
                'извлечёт сертификаты и закроется, отчёт останется в файле log_*.txt.\n\n'
                'Чтобы снова открыть это окно и поменять настройки, запустите программу '
                'с ключом --gui или поставьте ShowGui = yes в config.ini.')

    def current_template(self):
        return self.template_edit.text() or template_for_preset(self.current_preset())

    def current_date_format(self):
        return (self.date_format_edit.text()
                or date_format_for_preset(self.current_date_format_preset()))

    def update_preview(self):
        filename = build_filename(self.preview_fields, self.current_template())
        self.preview_label.setText(f'Пример имени файла: {filename}.cer')

    def reload_preview_fields(self):
        """Предпросмотр по первому реальному сертификату, иначе по примеру."""
        date_format = self.current_date_format()
        self.preview_fields = (read_first_certificate_fields(self.input_folder, date_format)
                               or example_fields(date_format))
        self.update_preview()

    def on_input_folder_changed(self, text):
        self.input_folder_edit.setToolTip(text)
        self.settings.input_folder = text
        self.save_config()
        self.reload_preview_fields()

    def on_output_folder_changed(self, text):
        self.output_folder_edit.setToolTip(text)
        self.settings.output_folder = text
        self.save_config()

    def select_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Выберите папку ввода', self.input_folder or os.path.expanduser('~'))
        if folder:
            self.input_folder_edit.setText(folder)

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Выберите выходную папку', self.output_folder or os.path.expanduser('~'))
        if folder:
            self.output_folder_edit.setText(folder)

    def run_parser(self):
            # Инициализация логгера при нажатии кнопки "Запустить"
            self.log_filename = start_logging()

            if not (self.input_folder and self.output_folder):
                QMessageBox.warning(self, 'Внимание', 'Выберите папки ввода и вывода перед запуском')
                return

            stats = parse_p7b_files(self.input_folder, self.output_folder,
                                    template=self.current_template(),
                                    only_user_certs=self.settings.only_user_certs,
                                    extract_attribute_certs=self.settings.extract_attribute_certs,
                                    date_format=self.current_date_format())

            report = (f"Обработано файлов .p7b: {stats['files']}\n\n"
                      f"Сертификаты: сохранено {stats['saved']}, дубликатов {stats['duplicates']}\n"
                      f"Атрибутные сертификаты: сохранено {stats['saved_attribute']}, "
                      f"дубликатов {stats['duplicates_attribute']}\n\n"
                      f"Пропущено сертификатов УЦ/ЦАС: {stats['skipped_ca']}\n"
                      f"Пропущено атрибутных (опция выключена): {stats['skipped_attribute']}\n"
                      f"Ошибок: {stats['errors']}")
            if stats['saved'] or stats['saved_attribute']:
                QMessageBox.information(self, 'Готово', f'Извлечение завершено успешно!\n\n{report}')
            else:
                QMessageBox.warning(self, 'Готово', f'Ничего не сохранено.\n\n{report}')



def start_logging():
    """Отчёт о работе всегда пишется в файл: без окна показать его негде."""
    log_filename = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    logging.basicConfig(filename=log_filename, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    return log_filename


def echo(message):
    """У exe, собранного с --noconsole, stdout нет — печатать туда нельзя."""
    if sys.stdout is not None:
        try:
            print(message)
        except (OSError, ValueError):
            pass


def run_without_gui(settings):
    """Извлечение без окна: настройки берутся из config.ini. Возвращает код возврата."""
    start_logging()

    if not (settings.input_folder and settings.output_folder):
        message = ('В config.ini не заданы InputFolder и OutputFolder. '
                   'Запустите программу с ключом --gui и выберите папки.')
        logging.error(message)
        echo(message)
        return 2

    stats = parse_p7b_files(settings.input_folder, settings.output_folder,
                            template=settings.template(),
                            only_user_certs=settings.only_user_certs,
                            extract_attribute_certs=settings.extract_attribute_certs,
                            date_format=settings.date_format())

    report = ("Обработано файлов .p7b: {files}; "
              "сертификатов сохранено: {saved}, дубликатов: {duplicates}; "
              "атрибутных сохранено: {saved_attribute}, дубликатов: {duplicates_attribute}; "
              "пропущено УЦ/ЦАС: {skipped_ca}, пропущено атрибутных: {skipped_attribute}; "
              "ошибок: {errors}".format(**stats))
    logging.info(report)
    echo(report)
    return 0 if (stats['saved'] or stats['saved_attribute']) else 1


def run_with_gui(settings):
    app = QApplication(sys.argv)
    window = CertificateParserApp(settings)
    window.show()
    return app.exec_()


if __name__ == '__main__':
    settings = Settings().load()

    # Ключи командной строки перекрывают ShowGui из config.ini на один запуск.
    if '--gui' in sys.argv[1:]:
        show_gui = True
    elif '--no-gui' in sys.argv[1:]:
        show_gui = False
    else:
        show_gui = settings.show_gui

    sys.exit(run_with_gui(settings) if show_gui else run_without_gui(settings))
