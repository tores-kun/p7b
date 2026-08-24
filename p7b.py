# -*- coding: utf-8 -*-
"""Извлечение сертификатов из .p7b и сохранение их в .cer.

Имя выходного файла собирается по шаблону из полей сертификата, см. FIELDS.
"""
import os
import re
import logging
from collections import OrderedDict

from asn1crypto import cms

# Поля, доступные для подстановки в шаблон имени файла.
# ключ -> (подпись для GUI, пример значения)
FIELDS = OrderedDict([
    ('CN',             ('CN (ФИО/наименование)',    'Иванов Иван Иванович')),
    ('surname',        ('Фамилия',                  'Иванов')),
    ('given_name',     ('Имя и отчество',           'Иван Иванович')),
    ('first_name',     ('Имя',                      'Иван')),
    ('serial',         ('Номер сертификата',        '4d2a9f31e7')),
    ('sok_id',         ('ID СОК',                   '8ef85dc4ce04892f98303410923936870cedca33')),
    ('subject_id',     ('Идентификатор в теме',     '1234567A890PB1')),
    ('unp',            ('УНП',                      '191234567')),
    ('org',            ('Организация',              'ООО Ромашка')),
    ('unit',           ('Подразделение',            'Бухгалтерия')),
    ('position',       ('Должность',                'Директор')),
    ('email',          ('Email',                    'ivanov@example.by')),
    ('thumbprint',     ('Отпечаток SHA-1',          'f18c9703d00d12938af970a56b523f588d139ea0')),
    ('valid_from',     ('Действителен с',           '2026-08-21')),
    ('valid_to',       ('Действителен по',          '2027-08-21')),
    ('issuer',         ('Издатель',                 'Республиканский УЦ ГосСУОК')),
])

# Готовые варианты имени файла: ключ -> (подпись для GUI, шаблон)
PRESETS = OrderedDict([
    ('CN',                 ('CN (ФИО/наименование)',          '{CN}')),
    ('surname',            ('Фамилия',                        '{surname}')),
    ('serial',             ('Номер сертификата',              '{serial}')),
    ('sok_id',             ('ID СОК',                         '{sok_id}')),
    ('CN_serial',          ('CN + номер сертификата',         '{CN}_{serial}')),
    ('surname_serial',     ('Фамилия + номер сертификата',    '{surname}_{serial}')),
    ('CN_sok_id',          ('CN + ID СОК',                    '{CN}_{sok_id}')),
    ('CN_serial_surname',  ('CN + номер + фамилия',           '{CN}_{serial}_{surname}')),
    ('custom',             ('Свой шаблон…',                   '')),
])

DEFAULT_PRESET = 'CN_serial_surname'
DEFAULT_TEMPLATE = PRESETS[DEFAULT_PRESET][1]

# Национальные OID ГосСУОК (см. "Перечень объектных уникальных идентификаторов" nces.by).
# asn1crypto отдаёт неизвестные OID строкой, поэтому сверяем по окончанию.
_UNP_OID_SUFFIX = '112.1.2.1.1.1.1.2'          # УНП — атрибут организации (tax-id)
_ORG_UNIT_OID_SUFFIX = '112.1.2.1.1.5.2'       # Подразделение (org-unit) — в сертификатах ЮЛ
_ORG_POSITION_OID_SUFFIX = '112.1.2.1.1.5.1'   # Место работы и должность (org-position)
_PRIV_NUM_OID_SUFFIX = '112.1.2.1.1.1.1.1'     # Личный номер (priv-num) — в сертификатах ЮЛ

# В реальных сертификатах ГосСУОК УНП, должность и личный номер представителя
# оказались вынесены в extensions, а не в атрибуты subject (расходится с
# профилем из ППС ЮЛ, но подтверждено разбором настоящего сертификата).

_INVALID_CHARS = re.compile(r'[\\/*?:"<>|\x00-\x1f]')
_PLACEHOLDER = re.compile(r'\{(\w+)\}')

MAX_NAME_LENGTH = 150


def template_for_preset(preset, custom_template=''):
    """Шаблон имени по выбранному пресету."""
    if preset == 'custom':
        return custom_template or DEFAULT_TEMPLATE
    label_template = PRESETS.get(preset)
    return label_template[1] if label_template else DEFAULT_TEMPLATE


def clean_filename(filename):
    """Убрать из имени символы, недопустимые в файловой системе."""
    cleaned = _INVALID_CHARS.sub('_', filename)
    cleaned = re.sub(r'_{2,}', '_', cleaned)
    cleaned = cleaned.strip(' ._-')
    return cleaned[:MAX_NAME_LENGTH].strip(' ._-')


def _text(value):
    """Привести значение атрибута темы к строке (атрибут может быть списком)."""
    if value is None:
        return ''
    if isinstance(value, (list, tuple, set)):
        return ' '.join(_text(item) for item in value if item)
    return str(value).strip()


def _subject_oid(subject, oid_suffix):
    for key, value in subject.items():
        if key.endswith(oid_suffix):
            return _text(value)
    return ''


_CONTROL_CHARS = re.compile(r'[\x00-\x1f]')


def _der_string_content(data):
    """Достать содержимое DER-примитива (TLV) как текст.

    Значения нераспознанных asn1crypto national-OID-расширений отдаются
    как сырые DER-байты вложенного ASN.1-значения (обычно строка) —
    заголовок тега/длины нужно снять вручную. BMPString (тег 0x1E) хранит
    текст в UTF-16BE — иначе между символами остаются нулевые байты,
    которые clean_filename превращает в «_» между цифрами.
    """
    if not data or len(data) < 2:
        return ''
    tag = data[0] & 0x1f
    length = data[1]
    if length & 0x80:
        num_bytes = length & 0x7f
        offset = 2 + num_bytes
        length = int.from_bytes(data[2:offset], 'big')
    else:
        offset = 2
    content = data[offset:offset + length]
    if tag == 0x1e:
        try:
            text = content.decode('utf-16-be')
        except UnicodeDecodeError:
            text = content.decode('utf-8', errors='replace')
    else:
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            text = content.decode('cp1251', errors='replace')
    return _CONTROL_CHARS.sub('', text).strip()


def _certificate_extension(certificate, oid_suffix):
    """Значение расширения сертификата (не атрибута subject) по окончанию OID.

    В сертификатах ГосСУОК некоторые национальные атрибуты (например, УНП
    организации) вынесены не в subject, а в отдельное extension.
    """
    try:
        extensions = certificate['tbs_certificate']['extensions']
    except (ValueError, KeyError, AttributeError):
        return ''
    for extension in extensions:
        try:
            if extension['extn_id'].dotted.endswith(oid_suffix):
                return _der_string_content(extension['extn_value'].native)
        except (ValueError, KeyError, AttributeError):
            continue
    return ''


def _first_word(text):
    return text.split()[0] if text.split() else ''


def _subject_key_identifier(certificate):
    """ID СОК — Subject Key Identifier сертификата."""
    try:
        ski = certificate.key_identifier_value
        if ski is not None:
            return ski.native.hex()
    except (ValueError, KeyError, AttributeError):
        pass
    try:
        # Расширения нет — считаем идентификатор от открытого ключа.
        return certificate.public_key.sha1.hex()
    except (ValueError, KeyError, AttributeError):
        return ''


def extract_fields(certificate):
    """Собрать все поддерживаемые поля сертификата в словарь {ключ: строка}."""
    tbs = certificate['tbs_certificate']
    subject = tbs['subject'].native or {}
    issuer = tbs['issuer'].native or {}
    validity = tbs['validity']

    # OID 2.5.4.41 ('name'): "Имя" в сертификатах ФЛ, "Имя и отчество" в сертификатах ЮЛ.
    given_name = _text(subject.get('name'))

    return {
        'CN': _text(subject.get('common_name')),
        'surname': _text(subject.get('surname')),
        'given_name': given_name,
        'first_name': _first_word(given_name),
        'serial': format(tbs['serial_number'].native, 'x'),
        'sok_id': _subject_key_identifier(certificate),
        # УНП, личный номер и должность представителя ЮЛ — расширения сертификата,
        # не атрибуты subject.
        'unp': _subject_oid(subject, _UNP_OID_SUFFIX) or _certificate_extension(certificate, _UNP_OID_SUFFIX),
        'subject_id': _text(subject.get('serial_number')) or _certificate_extension(certificate, _PRIV_NUM_OID_SUFFIX),
        'org': _text(subject.get('organization_name')),
        'unit': (_text(subject.get('organizational_unit_name'))
                 or _subject_oid(subject, _ORG_UNIT_OID_SUFFIX)
                 or _certificate_extension(certificate, _ORG_UNIT_OID_SUFFIX)),
        'position': _certificate_extension(certificate, _ORG_POSITION_OID_SUFFIX) or _text(subject.get('title')),
        'email': _text(subject.get('email_address')),
        'thumbprint': certificate.sha1.hex(),
        'valid_from': validity['not_before'].native.strftime('%Y-%m-%d'),
        'valid_to': validity['not_after'].native.strftime('%Y-%m-%d'),
        'issuer': _text(issuer.get('common_name')),
    }


def example_fields():
    """Значения-заглушки для предпросмотра, когда читать нечего."""
    return {key: example for key, (_label, example) in FIELDS.items()}


def build_filename(fields, template):
    """Подставить поля в шаблон и получить имя файла без расширения.

    Отсутствующие поля подставляются пустой строкой, лишние разделители
    схлопываются — иначе шаблон «{CN}_{surname}» без фамилии дал бы «Иванов_».
    """
    name = _PLACEHOLDER.sub(lambda match: fields.get(match.group(1), ''), template)
    name = clean_filename(name)
    return name or fields.get('serial', '') or 'certificate'


def is_ca_certificate(certificate):
    """Сертификат удостоверяющего центра, а не пользователя.

    Расширение basicConstraints — главный признак: если оно есть, верим ему.
    Самоподписанность проверяем последней, иначе сертификат пользователя,
    выпущенный сам на себя, ошибочно попал бы в УЦ.
    """
    try:
        basic_constraints = certificate.basic_constraints_value
        if basic_constraints is not None:
            return bool(basic_constraints['ca'].native)
    except (ValueError, KeyError, AttributeError):
        pass
    try:
        key_usage = certificate.key_usage_value
        if key_usage is not None and 'key_cert_sign' in key_usage.native:
            return True
    except (ValueError, KeyError, AttributeError):
        pass
    tbs = certificate['tbs_certificate']
    return tbs['subject'].native == tbs['issuer'].native


def _target_path(output_dir, base_name, serial, cert_bytes):
    """Путь для сохранения. None — такой сертификат уже сохранён раньше.

    При совпадении имён к имени дописывается номер сертификата (выбор
    пользователя), а счётчик добавляется только если и это не помогло.
    """
    candidates = [base_name]
    if serial and serial not in base_name:
        candidates.append('{}_{}'.format(base_name, serial))
    candidates.extend('{}_{}_{}'.format(base_name, serial, i) for i in range(1, 100))

    for candidate in candidates:
        path = os.path.join(output_dir, clean_filename(candidate) + '.cer')
        if not os.path.exists(path):
            return path
        try:
            with open(path, 'rb') as existing:
                if existing.read() == cert_bytes:
                    return None
        except OSError:
            continue
    return None


def parse_p7b(p7b_file_path, output_dir, template=DEFAULT_TEMPLATE, only_user_certs=False, stats=None):
    """Извлечь сертификаты из одного .p7b."""
    if stats is None:
        stats = {'saved': 0, 'duplicates': 0, 'skipped_ca': 0, 'errors': 0, 'files': 0}

    try:
        with open(p7b_file_path, 'rb') as p7b_file:
            p7b_data = p7b_file.read()
    except OSError as error:
        logging.error("Не удалось прочитать файл %s: %s", p7b_file_path, error)
        stats['errors'] += 1
        return stats

    try:
        content_info = cms.ContentInfo.load(p7b_data)
        certificates = content_info['content']['certificates']
    except Exception as error:
        logging.error("Ошибка при загрузке P7B-файла %s: %s", p7b_file_path, error)
        stats['errors'] += 1
        return stats

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    stats['files'] += 1

    for index, cert in enumerate(certificates):
        try:
            certificate = cert.chosen
            if only_user_certs and is_ca_certificate(certificate):
                stats['skipped_ca'] += 1
                logging.info("Пропущен сертификат УЦ из %s (#%s)", p7b_file_path, index)
                continue

            fields = extract_fields(certificate)
            base_name = build_filename(fields, template)
            cert_bytes = cert.dump()

            cert_file_path = _target_path(output_dir, base_name, fields['serial'], cert_bytes)
            if cert_file_path is None:
                stats['duplicates'] += 1
                logging.info("Сертификат %s уже сохранён, пропускаем", base_name)
                continue

            with open(cert_file_path, 'wb') as cert_file:
                cert_file.write(cert_bytes)
            stats['saved'] += 1
            logging.info("Сертификат сохранен в: %s", cert_file_path)
        except Exception as error:
            stats['errors'] += 1
            logging.warning(
                "Пропускаем сертификат #%s из %s, не удалось извлечь данные: %s",
                index, p7b_file_path, error)
            continue

    return stats


def parse_p7b_files(input_folder, output_folder, template=DEFAULT_TEMPLATE, only_user_certs=False):
    """Обработать все .p7b из входной папки. Возвращает статистику обработки."""
    stats = {'saved': 0, 'duplicates': 0, 'skipped_ca': 0, 'errors': 0, 'files': 0}

    if not input_folder or not os.path.isdir(input_folder):
        logging.error("Ошибка: Папка %s не существует.", input_folder)
        stats['errors'] += 1
        return stats

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for filename in sorted(os.listdir(input_folder)):
        if filename.lower().endswith('.p7b'):
            parse_p7b(os.path.join(input_folder, filename), output_folder,
                      template=template, only_user_certs=only_user_certs, stats=stats)

    return stats


def read_first_certificate_fields(input_folder):
    """Поля первого найденного сертификата — для предпросмотра имени в GUI."""
    if not input_folder or not os.path.isdir(input_folder):
        return None
    for filename in sorted(os.listdir(input_folder)):
        if not filename.lower().endswith('.p7b'):
            continue
        try:
            with open(os.path.join(input_folder, filename), 'rb') as p7b_file:
                content_info = cms.ContentInfo.load(p7b_file.read())
            for cert in content_info['content']['certificates']:
                certificate = cert.chosen
                if not is_ca_certificate(certificate):
                    return extract_fields(certificate)
        except Exception:
            continue
    return None


if __name__ == "__main__":
    from datetime import datetime
    from settings import Settings

    settings = Settings()
    settings.load()

    logging.basicConfig(
        filename="log_{}.txt".format(datetime.now().strftime('%Y-%m-%d_%H-%M-%S')),
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s')

    result = parse_p7b_files(
        settings.input_folder or r'./in',
        settings.output_folder or r'./out',
        template=settings.template(),
        only_user_certs=settings.only_user_certs)
    print("Сохранено: {saved}, дубликатов: {duplicates}, "
          "пропущено УЦ: {skipped_ca}, ошибок: {errors}".format(**result))
