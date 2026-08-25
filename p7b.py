# -*- coding: utf-8 -*-
"""Извлечение сертификатов из .p7b и сохранение их в .cer.

Имя выходного файла собирается по шаблону из полей сертификата, см. FIELDS.
"""
import os
import re
import logging
import hashlib
from collections import OrderedDict

from asn1crypto import cms, x509

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


# ППС атрибутных сертификатов (СТБ 34.101.19/67, "attribute-rca"): служебный СОК
# ЦАС, подписывающий атрибутные сертификаты и их СОАС. По X.509 это не CA
# (basicConstraints.ca=False, key_cert_sign в keyUsage нет), поэтому
# is_ca_certificate() его не ловит — опознаём отдельно, по политике сертификата.
_ATTRIBUTE_SERVICE_POLICY_OID = '1.2.112.1.2.1.1.1.3.2.3'


def is_attribute_service_certificate(certificate):
    """СОК службы атрибутных сертификатов (ЦАС) — не пользовательский и не CA."""
    try:
        policies = certificate.certificate_policies_value
        if policies is None:
            return False
        return any(
            policy['policy_identifier'].dotted == _ATTRIBUTE_SERVICE_POLICY_OID
            for policy in policies
        )
    except (ValueError, KeyError, AttributeError):
        return False


def is_excluded_from_user_certs(certificate):
    """Сертификаты, которые флажок «Только сертификаты пользователя» должен убрать:
    вышестоящие УЦ и служебный СОК ЦАС (службы атрибутных сертификатов)."""
    return is_ca_certificate(certificate) or is_attribute_service_certificate(certificate)


def _der_sequence(value_bytes):
    """DER-заголовок SEQUENCE (0x30, definite length) поверх готового содержимого."""
    length = len(value_bytes)
    if length < 0x80:
        header = bytes([0x30, length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        header = bytes([0x30, 0x80 | len(length_bytes)]) + length_bytes
    return header + value_bytes


def _attribute_cert_standalone_bytes(cert):
    """DER атрибутного сертификата как самостоятельного объекта, а не как
    альтернативы CHOICE CertificateChoices.

    В CertificateChoices (RFC 5652) v1AttrCert/v2AttrCert помечены implicit-
    тегами [1]/[2] — cert.dump() отдаёт байты с этим переопределённым тегом
    (0xA1/0xA2) вместо родного универсального SEQUENCE (0x30). Такой файл
    сторонние программы (например, АвЭст ПМС) не распознают как *.acr —
    им нужен натуральный заголовок, как у самостоятельного AttributeCertificate.
    Implicit-тег не меняет кодировку содержимого (contents) — просто строим
    для него правильный внешний заголовок SEQUENCE вместо implicit-тега.
    """
    return _der_sequence(cert.chosen.contents)


def _target_path(output_dir, base_name, serial, cert_bytes, extension='.cer'):
    """Путь для сохранения. None — такой сертификат уже сохранён раньше.

    При совпадении имён к имени дописывается номер сертификата (выбор
    пользователя), а счётчик добавляется только если и это не помогло.
    """
    candidates = [base_name]
    if serial and serial not in base_name:
        candidates.append('{}_{}'.format(base_name, serial))
    candidates.extend('{}_{}_{}'.format(base_name, serial, i) for i in range(1, 100))

    for candidate in candidates:
        path = os.path.join(output_dir, clean_filename(candidate) + extension)
        if not os.path.exists(path):
            return path
        try:
            with open(path, 'rb') as existing:
                if existing.read() == cert_bytes:
                    return None
        except OSError:
            continue
    return None


def _attribute_cert_holder_serial(attr_cert):
    """Serial X.509-сертификата, к которому привязан атрибутный (Holder.baseCertificateID).

    В ГосСУОК атрибутный сертификат обычно выпускается в паре с обычным
    сертификатом того же владельца — по этой ссылке подтягиваем его ФИО/
    организацию для имени файла.
    """
    try:
        base_id = attr_cert['ac_info']['holder']['base_certificate_id']
        if base_id.native is None:
            return ''
        return format(base_id['serial'].native, 'x')
    except (ValueError, KeyError, AttributeError, TypeError):
        return ''


def _attribute_cert_attributes_raw(attr_cert):
    """Сырой словарь attrCertInfo.attributes (АС ГосСУОК, СТБ 34.101.67-2014).

    Профиль описывает это поле как плоский набор атрибутов (countryName,
    organizationName, title, УНП и т.д.) — по оформлению документа похоже
    на RDN-последовательность (как subject обычного сертификата), а не на
    стандартный RFC 5755 SET OF Attribute. Точный ASN.1-тег не подтверждён
    на реальном образце, поэтому пробуем оба варианта декодирования и молча
    возвращаем пустой словарь, если не подошёл ни один — хуже, чем пустое
    поле, от этого не станет.
    """
    try:
        raw = attr_cert['ac_info']['attributes'].dump()
    except (ValueError, KeyError, AttributeError):
        return {}

    try:
        native = x509.Name.load(raw).native
        if native:
            return native
    except Exception:
        pass

    result = {}
    try:
        for attribute in cms.Attributes.load(raw):
            values = attribute['values']
            if len(values):
                result[attribute['type'].dotted] = _text(values[0].native)
    except Exception:
        pass
    return result


def _attribute_cert_org_fields(attr_cert):
    """org/unit/position/unp из attrCertInfo.attributes, если удалось прочитать."""
    raw = _attribute_cert_attributes_raw(attr_cert)
    if not raw:
        return {}

    def get(name_key, oid_suffix):
        value = raw.get(name_key)
        if value:
            return _text(value)
        for key, val in raw.items():
            if isinstance(key, str) and key.endswith(oid_suffix):
                return _text(val)
        return ''

    return {
        'org': get('organization_name', '2.5.4.10'),
        'unit': get('organizational_unit_name', '2.5.4.11'),
        'position': get('title', '2.5.4.12'),
        'unp': get('', _UNP_OID_SUFFIX),
    }


def extract_attribute_fields(attr_cert, standalone_bytes, linked_fields=None):
    """Поля атрибутного сертификата (AttributeCertificateV1/V2) для имени файла.

    У атрибутного сертификата нет subject в привычном смысле — ФИО и т.п.
    берутся из связанного X.509-сертификата (linked_fields), если он
    нашёлся в этом же .p7b; org/unit/position/unp сначала пробуем прочитать
    из собственного attrCertInfo.attributes АС (см. _attribute_cert_org_fields)
    и, если не вышло, тоже берём из связанного сертификата. serial/срок
    действия — свои, этого атрибутного сертификата; отпечаток считается от
    standalone_bytes (см. _attribute_cert_standalone_bytes) — тех же байт,
    что и сохраняются в файл.
    """
    ac_info = attr_cert['ac_info']
    validity = ac_info['att_cert_validity_period']

    fields = {key: '' for key in FIELDS}
    if linked_fields:
        fields.update(linked_fields)

    own_org_fields = _attribute_cert_org_fields(attr_cert)
    for key in ('org', 'unit', 'position', 'unp'):
        if own_org_fields.get(key):
            fields[key] = own_org_fields[key]

    fields['serial'] = format(ac_info['serial_number'].native, 'x')
    fields['valid_from'] = validity['not_before_time'].native.strftime('%Y-%m-%d')
    fields['valid_to'] = validity['not_after_time'].native.strftime('%Y-%m-%d')
    fields['thumbprint'] = hashlib.sha1(standalone_bytes).hexdigest()
    return fields


def _save_extracted(output_dir, fields, template, cert_bytes, extension, stats, label, p7b_file_path, kind='cert'):
    """Сохранить извлечённый сертификат/атрибутный сертификат по шаблону имени.

    kind различает счётчики в stats: 'cert' -> saved/duplicates,
    'attribute' -> saved_attribute/duplicates_attribute — чтобы в отчёте
    обычные сертификаты и атрибутные не смешивались в одну сумму.
    """
    saved_key = 'saved' if kind == 'cert' else 'saved_attribute'
    duplicates_key = 'duplicates' if kind == 'cert' else 'duplicates_attribute'

    base_name = build_filename(fields, template)
    cert_file_path = _target_path(output_dir, base_name, fields['serial'], cert_bytes, extension=extension)
    if cert_file_path is None:
        stats[duplicates_key] += 1
        logging.info("%s %s уже сохранён, пропускаем", label, base_name)
        return
    with open(cert_file_path, 'wb') as cert_file:
        cert_file.write(cert_bytes)
    stats[saved_key] += 1
    logging.info("%s сохранён в: %s", label, cert_file_path)


def parse_p7b(p7b_file_path, output_dir, template=DEFAULT_TEMPLATE, only_user_certs=False,
              extract_attribute_certs=False, stats=None):
    """Извлечь сертификаты из одного .p7b."""
    if stats is None:
        stats = {'saved': 0, 'duplicates': 0, 'saved_attribute': 0, 'duplicates_attribute': 0, 'skipped_ca': 0, 'skipped_attribute': 0, 'errors': 0, 'files': 0}

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

    # Атрибутные сертификаты ссылаются на «базовый» X.509-сертификат того же
    # владельца по serial (Holder.baseCertificateID) — строим карту заранее,
    # независимо от порядка записей внутри .p7b.
    fields_by_serial = {}
    if extract_attribute_certs:
        for cert in certificates:
            if cert.name == 'certificate':
                try:
                    fields = extract_fields(cert.chosen)
                    fields_by_serial[fields['serial']] = fields
                except Exception:
                    continue

    for index, cert in enumerate(certificates):
        try:
            if cert.name != 'certificate':
                if not (extract_attribute_certs and cert.name in ('v1_attr_cert', 'v2_attr_cert')):
                    # СОК ЮЛ в ГосСУОК бывает совмещён с атрибутным сертификатом
                    # (AttributeCertificateV1/V2) — это не X.509-сертификат,
                    # извлекать/сохранять как .cer нечего (если не включена опция).
                    stats['skipped_attribute'] += 1
                    logging.info(
                        "Пропущена запись #%s из %s: не X.509-сертификат (%s)",
                        index, p7b_file_path, cert.name)
                    continue

                attr_cert = cert.chosen
                standalone_bytes = _attribute_cert_standalone_bytes(cert)
                linked_serial = _attribute_cert_holder_serial(attr_cert)
                fields = extract_attribute_fields(attr_cert, standalone_bytes, fields_by_serial.get(linked_serial))
                _save_extracted(output_dir, fields, template, standalone_bytes, '.acr',
                                 stats, 'Атрибутный сертификат', p7b_file_path, kind='attribute')
                continue

            certificate = cert.chosen
            if only_user_certs and is_excluded_from_user_certs(certificate):
                stats['skipped_ca'] += 1
                logging.info("Пропущен сертификат УЦ/ЦАС из %s (#%s)", p7b_file_path, index)
                continue

            fields = extract_fields(certificate)
            _save_extracted(output_dir, fields, template, cert.dump(), '.cer',
                             stats, 'Сертификат', p7b_file_path)
        except Exception as error:
            stats['errors'] += 1
            logging.warning(
                "Пропускаем сертификат #%s из %s, не удалось извлечь данные: %s",
                index, p7b_file_path, error)
            continue

    return stats


def parse_p7b_files(input_folder, output_folder, template=DEFAULT_TEMPLATE, only_user_certs=False,
                     extract_attribute_certs=False):
    """Обработать все .p7b из входной папки. Возвращает статистику обработки."""
    stats = {'saved': 0, 'duplicates': 0, 'saved_attribute': 0, 'duplicates_attribute': 0, 'skipped_ca': 0, 'skipped_attribute': 0, 'errors': 0, 'files': 0}

    if not input_folder or not os.path.isdir(input_folder):
        logging.error("Ошибка: Папка %s не существует.", input_folder)
        stats['errors'] += 1
        return stats

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for filename in sorted(os.listdir(input_folder)):
        if filename.lower().endswith('.p7b'):
            parse_p7b(os.path.join(input_folder, filename), output_folder,
                      template=template, only_user_certs=only_user_certs,
                      extract_attribute_certs=extract_attribute_certs, stats=stats)

    return stats


def read_first_certificate_fields(input_folder):
    """Поля первого найденного пользовательского сертификата — для предпросмотра имени в GUI."""
    if not input_folder or not os.path.isdir(input_folder):
        return None
    for filename in sorted(os.listdir(input_folder)):
        if not filename.lower().endswith('.p7b'):
            continue
        try:
            with open(os.path.join(input_folder, filename), 'rb') as p7b_file:
                content_info = cms.ContentInfo.load(p7b_file.read())
            for cert in content_info['content']['certificates']:
                if cert.name != 'certificate':
                    continue
                certificate = cert.chosen
                if not is_excluded_from_user_certs(certificate):
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
        only_user_certs=settings.only_user_certs,
        extract_attribute_certs=settings.extract_attribute_certs)
    print("Сертификатов сохранено: {saved}, дубликатов: {duplicates}; "
          "атрибутных сохранено: {saved_attribute}, дубликатов: {duplicates_attribute}; "
          "пропущено УЦ/ЦАС: {skipped_ca}, пропущено атрибутных (опция выключена): {skipped_attribute}; "
          "ошибок: {errors}".format(**result))
