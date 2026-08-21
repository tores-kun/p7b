# -*- coding: utf-8 -*-
import sys, os, logging
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
                             QFileDialog, QMessageBox, QLabel, QSizePolicy, QComboBox,
                             QLineEdit, QCheckBox, QMenu)
from PyQt5.QtCore import Qt
from p7b import (parse_p7b_files, FIELDS, PRESETS, build_filename, template_for_preset,
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
        self.setGeometry(300, 300, 560, 620)

        # Load input and output folders from the configuration
        if self.input_folder:
            self.input_folder_label = QLabel(f'Выбрана папка: {self.input_folder}', self)
        else:
            self.input_folder_label = QLabel('Выберите папку с P7B-файлами:', self)

        self.input_folder_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 2px;")

        # Внешний контейнер для группировки виджетов с текстом и кнопкой
        input_container = QVBoxLayout()

        input_folder_widget = QWidget(self)  # Виджет для объединения label и button
        input_folder_layout = QVBoxLayout(input_folder_widget)
        input_folder_layout.addWidget(self.input_folder_label)

        self.input_folder_button = QPushButton('Выберите папку с P7B-файлами', self)
        self.input_folder_button.clicked.connect(self.select_input_folder)
        self.input_folder_button.setStyleSheet("color: white; background-color: green; border-radius: 5px; padding: 2px; font-size: 14px; margin-top: 0px;")
        input_folder_layout.addWidget(self.input_folder_button)

        # Установка размера для внешнего контейнера
        input_folder_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        input_container.addWidget(input_folder_widget, alignment=Qt.AlignTop | Qt.AlignLeft)

        # Output folder label initialization
        if self.output_folder:
            self.output_folder_label = QLabel(f'Выбрана папка: {self.output_folder}', self)
        else:
            self.output_folder_label = QLabel('Выберите папку куда будут извлечены .cer:', self)

        self.output_folder_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 2px;")
        output_container = QVBoxLayout()
        output_folder_widget = QWidget(self)  # Виджет для объединения label и button
        output_folder_layout = QVBoxLayout(output_folder_widget)
        output_folder_layout.addWidget(self.output_folder_label)
        self.output_folder_button = QPushButton('Выберите папку куда будут извлечены .cer', self)
        self.output_folder_button.clicked.connect(self.select_output_folder)
        self.output_folder_button.setStyleSheet("color: white; background-color: green; border-radius: 5px; padding: 5px; font-size: 14px; margin-left: 0px;")
        output_folder_layout.addWidget(self.output_folder_button)
        output_folder_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        output_container.addWidget(output_folder_widget, alignment=Qt.AlignTop | Qt.AlignLeft)

        naming_container = self.build_naming_ui()

        self.run_button = QPushButton('Запустить', self)
        self.run_button.clicked.connect(self.run_parser)
        self.run_button.setStyleSheet("color: white; background-color: green; border-radius: 5px; padding: 5px; font-size: 14px;")

        self.author_label = QLabel('© Белоусов А.В.', self)

        button_layout = QVBoxLayout()
        button_layout.addWidget(self.run_button, alignment=Qt.AlignTop | Qt.AlignRight)
        button_layout.addWidget(self.author_label, alignment=Qt.AlignBottom | Qt.AlignRight)

        main_layout = QVBoxLayout(self)
        main_layout.addLayout(input_container)  
        main_layout.addLayout(output_container)
        main_layout.addLayout(naming_container)
        main_layout.addLayout(button_layout)

        # Применение стилей к виджетам через qss.
        # Фоновой картинки нет, поэтому подложки под текстом больше не нужны.
        self.setStyleSheet("""
            CertificateParserApp {
                background-color: #f1f4f2;
            }
            QLabel {
                color: black;
                background-color: transparent;
                padding: 5px;
            }
            QLabel#preview {
                background-color: white;
                border: 1px solid #c9d4cd;
                border-radius: 5px;
                font-style: italic;
            }
        """)

    def build_naming_ui(self):
        """Блок выбора имени сертификата: пресет, свой шаблон, предпросмотр."""
        naming_container = QVBoxLayout()
        naming_widget = QWidget(self)
        naming_layout = QVBoxLayout(naming_widget)

        naming_title = QLabel('Из чего собирать имя файла сертификата:', self)
        naming_title.setStyleSheet("font-weight: bold; font-size: 14px; padding: 2px;")
        naming_layout.addWidget(naming_title)

        self.preset_combo = QComboBox(self)
        for preset_key, (label, _template) in PRESETS.items():
            self.preset_combo.addItem(label, preset_key)
        self.preset_combo.setCurrentIndex(max(0, self.preset_combo.findData(self.settings.preset)))
        self.preset_combo.currentIndexChanged.connect(self.on_preset_changed)
        naming_layout.addWidget(self.preset_combo)

        template_row = QHBoxLayout()
        self.template_edit = QLineEdit(self)
        self.template_edit.setPlaceholderText('{fio}_{serial}')
        self.template_edit.textChanged.connect(self.on_template_changed)
        template_row.addWidget(self.template_edit)

        self.insert_field_button = QPushButton('+ поле', self)
        self.insert_field_button.setStyleSheet("color: white; background-color: green; border-radius: 5px; padding: 5px; font-size: 14px;")
        self.insert_field_button.setMenu(self.build_fields_menu())
        template_row.addWidget(self.insert_field_button)
        naming_layout.addLayout(template_row)

        self.preview_label = QLabel(self)
        self.preview_label.setObjectName('preview')
        self.preview_label.setWordWrap(True)
        naming_layout.addWidget(self.preview_label)

        self.only_user_certs_checkbox = QCheckBox('Только сертификаты пользователя (без вышестоящих УЦ)', self)
        self.only_user_certs_checkbox.setChecked(self.settings.only_user_certs)
        self.only_user_certs_checkbox.stateChanged.connect(self.on_only_user_certs_changed)
        naming_layout.addWidget(self.only_user_certs_checkbox)

        self.headless_checkbox = QCheckBox('Запускать без окна — сразу извлекать и закрываться', self)
        self.headless_checkbox.setChecked(not self.settings.show_gui)
        self.headless_checkbox.setToolTip('Чтобы снова открыть это окно, запустите программу с ключом --gui')
        self.headless_checkbox.stateChanged.connect(self.on_headless_changed)
        naming_layout.addWidget(self.headless_checkbox)

        naming_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        naming_container.addWidget(naming_widget, alignment=Qt.AlignTop)

        self.apply_preset_to_template_edit()
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
        self.update_preview()

    def on_preset_changed(self):
        self.settings.preset = self.current_preset()
        self.apply_preset_to_template_edit()
        self.save_config()

    def on_template_changed(self, text):
        if self.current_preset() == 'custom':
            self.settings.custom_template = text
            self.save_config()
        self.update_preview()

    def on_only_user_certs_changed(self, state):
        self.settings.only_user_certs = bool(state)
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

    def update_preview(self):
        filename = build_filename(self.preview_fields, self.current_template())
        self.preview_label.setText(f'Пример имени файла: {filename}.cer')

    def reload_preview_fields(self):
        """Предпросмотр по первому реальному сертификату, иначе по примеру."""
        self.preview_fields = read_first_certificate_fields(self.input_folder) or example_fields()
        self.update_preview()

    def select_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Выберите папку ввода', self.input_folder or os.path.expanduser('~'))
        if folder:
            self.input_folder_label.setText(f'Выбрана папка: {folder}')
            self.settings.input_folder = folder
            self.save_config()
            self.reload_preview_fields()

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Выберите выходную папку', self.output_folder or os.path.expanduser('~'))
        if folder:
            self.output_folder_label.setText(f'Выбрана папка: {folder}')
            self.settings.output_folder = folder
            self.save_config()

    def run_parser(self):
            # Инициализация логгера при нажатии кнопки "Запустить"
            self.log_filename = start_logging()

            if not (self.input_folder and self.output_folder):
                QMessageBox.warning(self, 'Внимание', 'Выберите папки ввода и вывода перед запуском')
                return

            stats = parse_p7b_files(self.input_folder, self.output_folder,
                                    template=self.current_template(),
                                    only_user_certs=self.settings.only_user_certs)

            report = (f"Обработано файлов .p7b: {stats['files']}\n"
                      f"Сохранено сертификатов: {stats['saved']}\n"
                      f"Пропущено дубликатов: {stats['duplicates']}\n"
                      f"Пропущено сертификатов УЦ: {stats['skipped_ca']}\n"
                      f"Ошибок: {stats['errors']}")
            if stats['saved']:
                QMessageBox.information(self, 'Готово', f'Извлечение завершено успешно!\n\n{report}')
            else:
                QMessageBox.warning(self, 'Готово', f'Ни один сертификат не сохранён.\n\n{report}')



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
                            only_user_certs=settings.only_user_certs)

    report = ("Обработано файлов .p7b: {files}, сохранено сертификатов: {saved}, "
              "дубликатов: {duplicates}, пропущено УЦ: {skipped_ca}, "
              "ошибок: {errors}".format(**stats))
    logging.info(report)
    echo(report)
    return 0 if stats['saved'] else 1


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
