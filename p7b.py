import os
from asn1crypto import cms
import re
import logging
from datetime import datetime

# Настройка логгера
log_filename = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
# logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def clean_filename(filename):
    # Заменить все недопустимые символы на нижнее подчеркивание
    cleaned_filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
    return cleaned_filename

def parse_p7b_files(input_folder, output_folder):
    # Проверка наличия исходной папки
    if not os.path.exists(input_folder):
        logging.error(f"Ошибка: Папка {input_folder} не существует.")
        return

    # Создание выходной папки, если её нет
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Перебор файлов в исходной папке
    for filename in os.listdir(input_folder):
        if filename.endswith(".p7b"):
            p7b_file_path = os.path.join(input_folder, filename)

            # Загрузка и обработка P7B-файла
            parse_p7b(p7b_file_path, output_folder)

def parse_p7b(p7b_file_path, output_dir):
    # Загрузка P7B-файла
    with open(p7b_file_path, 'rb') as p7b_file:
        p7b_data = p7b_file.read()

    # Извлечение сертификатов
    try:
        content_info = cms.ContentInfo.load(p7b_data)
    except Exception as e:
        logging.error(f"Ошибка при загрузке P7B-файла {p7b_file_path}: {e}")
        return

    # Создание выходной папки, если её нет
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Сохранение сертификатов в формате CER
    for i, cert in enumerate(content_info['content']['certificates']):
        try:
            # Изменения в API asn1crypto
            subject = cert.chosen['tbs_certificate']['subject']
            common_name = subject.native['common_name']
            serial_number = hex(cert.chosen['tbs_certificate']['serial_number'].native)[2:]  # преобразование в 16 систему исчисления и удаление префикса "0x"

            # Поиск фамилии клиента в атрибутах
            surname_attr = subject.native.get('surname')
            surname = surname_attr

            if surname is None:
                filename = f"{common_name}_{serial_number}.cer"
            else:     
                filename = f"{common_name}_{serial_number}_{surname}.cer"


            cleaned_filename = clean_filename(filename)

            cert_file_path = os.path.join(output_dir, cleaned_filename)
            with open(cert_file_path, 'wb') as cert_file:
                cert_file.write(cert.dump())
            logging.info(f"Сертификат сохранен в: {cert_file_path}")
            # print(f"Сертификат сохранен в: {cert_file_path}")
        except KeyError as e:
            logging.warning(f"Пропускаем сертификат {common_name}, так как не удалось извлечь данные: {e}")
            # print(f"Пропускаем сертификат {common_name}, так как не удалось извлечь данные: {e}")
            continue

# def remove_certificates(output_dir):
#     # Шаблоны имен сертификатов для удаления
#     certificates_to_remove = ["Корневой удостоверяющий центр ГосСУОК*.cer",
#                               "Республиканский удостоверяющий центр ГосСУОК*.cer"]

#     for cert_pattern in certificates_to_remove:
#         # Ищем все сертификаты, соответствующие шаблону
#         matching_certificates = [cert for cert in os.listdir(output_dir) if cert.startswith(cert_pattern)]

#         for cert_name in matching_certificates:
#             cert_path = os.path.join(output_dir, cert_name)
#             if os.path.exists(cert_path):
#                 os.remove(cert_path)
#                 logging.info(f"Сертификат удален: {cert_path}")
#                 print(f"Сертификат удален: {cert_path}")
#             else:
#                 logging.warning(f"Сертификат не найден: {cert_path}")
#                 print(f"Сертификат не найден: {cert_path}")

if __name__ == "__main__":
    input_folder = r'./in'
    output_folder = r'./out'

    parse_p7b_files(input_folder, output_folder)