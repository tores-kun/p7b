import sys, os, configparser, pkg_resources, logging
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox, QLabel, QSizePolicy
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
from p7b import parse_p7b_files
from datetime import datetime

def get_image_data():
    try:
        return pkg_resources.resource_string(__name__, 'default_background_image.jpg')
    except FileNotFoundError:
        try:
            # Пытаемся загрузить изображение из текущего каталога
            with open('default_background_image.jpg', 'rb') as file:
                return file.read()
        except FileNotFoundError:
            return b''  # Пустой байтовый объект, если изображение не найдено


def save_image_to_file(image_data, file_path):
    with open(file_path, 'wb') as file:
        file.write(image_data)

class CertificateParserApp(QWidget):
    def __init__(self):
        super().__init__()

        self.config = configparser.ConfigParser()
        self.config_file_path = 'config.ini'
        self.input_folder = None
        self.output_folder = None
        self.background_image_path = None
        self.log_filename = None
        self.load_config()
        self.init_ui()

    def load_config(self):
        if os.path.exists(self.config_file_path):
            self.config.read(self.config_file_path)
            self.input_folder = self.config.get('Paths', 'InputFolder', fallback='')
            self.output_folder = self.config.get('Paths', 'OutputFolder', fallback='')
            self.background_image_path = self.config.get('Paths', 'BackgroundImage', fallback='')

    def save_config(self):
        self.config['Paths'] = {'InputFolder': str(self.input_folder),
                                'OutputFolder': str(self.output_folder),
                                'BackgroundImage': str(self.background_image_path)}
        with open(self.config_file_path, 'w') as configfile:
            self.config.write(configfile)

    def init_ui(self):
        self.setWindowTitle('Извлечение всех .cer из .p7b')
        self.setGeometry(300, 300, 512, 512)

        # Загрузка изображения
        background_image = QLabel(self)
        if self.background_image_path and os.path.exists(self.background_image_path):
            pixmap = QPixmap(self.background_image_path)
        else:
            pixmap = QPixmap('default_background_image.jpg')  # Путь к изображению по умолчанию
        background_image.setPixmap(pixmap)
        background_image.setGeometry(0, 0, self.width(), self.height())

        # Сделать фон серым
        background_image.setStyleSheet("background-color:  #47A76A;")

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
        main_layout.addLayout(button_layout)

        # Применение стилей к виджетам через qss
        self.setStyleSheet("""
            QLabel, QPushButton {
                color: black;
                background-color: rgba(255, 255, 255, 100);
                border-radius: 5px;
                padding: 5px;
            }
        """)

    def select_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Выберите папку ввода', self.input_folder or os.path.expanduser('~'))
        if folder:
            self.input_folder_label.setText(f'Выбрана папка: {folder}')
            self.input_folder = folder
            self.save_config()

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Выберите выходную папку', self.output_folder or os.path.expanduser('~'))
        if folder:
            self.output_folder_label.setText(f'Выбрана папка: {folder}')
            self.output_folder = folder
            self.save_config()

    def run_parser(self):
            # Инициализация логгера при нажатии кнопки "Запустить"
            self.log_filename = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            logging.basicConfig(filename=self.log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

            try:
                if self.input_folder and self.output_folder:
                    parse_p7b_files(self.input_folder, self.output_folder)
                    QMessageBox.information(self, 'Готово', 'Извлечение завершено успешно!')
                else:
                    QMessageBox.warning(self, 'Внимание', 'Выберите папки ввода и вывода перед запуском')
            except AttributeError:
                pass  # Handle the case where folders are not selected yet



if __name__ == '__main__':
    image_data = get_image_data()
    save_image_to_file(image_data, 'default_background_image.jpg')
    app = QApplication(sys.argv)
    window = CertificateParserApp()
    window.show()
    sys.exit(app.exec_())