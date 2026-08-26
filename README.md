Извлечение сертификатов из файлов .p7b<br><br>

Это приложение на Python с использованием PyQt5 предоставляет простой интерфейс для извлечения сертификатов из файлов формата .p7b и сохранения их в формате .cer. <br>
Он также позволяет выбирать входную и выходную папки для обработки файлов и задавать, из каких полей сертификата собирается имя выходного файла.<br>

Основные функции: Извлечение сертификатов из файлов .p7b. Сохранение сертификатов в формате .cer. Настройка входной и выходной папок через графический интерфейс. Выбор полей сертификата, из которых собирается имя файла. Запуск без окна по настройкам из config.ini. <br><br>
<b>Выбор имени файла сертификата</b><br>
В окне приложения есть список «Из чего собирать имя файла сертификата»:<br>
CN (ФИО/наименование) · Фамилия · Номер сертификата · ID СОК · CN + номер сертификата · Фамилия + номер сертификата · CN + ID СОК · CN + номер + фамилия · Свой шаблон…<br>
Под списком показывается пример имени, посчитанный по первому сертификату из входной папки.<br><br>

Вариант «Свой шаблон…» открывает поле, куда поля подставляются кнопкой «+ поле»:<br>

<pre>
{CN}          CN (ФИО/наименование)   {org}         Организация
{surname}     Фамилия                 {unit}        Подразделение
{given_name}  Имя и отчество          {position}    Должность
{first_name}  Имя                     {email}       Email
{serial}      Номер сертификата       {thumbprint}  Отпечаток SHA-1
{sok_id}      ID СОК (Subject Key Identifier)       {valid_from}  Действителен с
{subject_id}  Идентификатор в теме    {valid_to}    Действителен по
{unp}         УНП                     {issuer}      Издатель
</pre>

Если поле в сертификате отсутствует, оно подставляется пустым, а лишние разделители убираются.<br>

<b>Формат даты</b> — список рядом с шаблоном задаёт, как выглядят <code>{valid_from}</code> и <code>{valid_to}</code>: ГГГГ-ММ-ДД, ДД.ММ.ГГГГ, ДД-ММ-ГГГГ, ГГГГММДД, ГГГГ-ММ, только год или «Свой формат…». Свой формат задаётся кодами strftime: <code>%Y</code> — год, <code>%m</code> — месяц, <code>%d</code> — день (например, <code>%m-%Y</code> даёт <code>08-2026</code>).<br>
Если по шаблону получились одинаковые имена (например, два сертификата одного Иванова при выборе «Фамилия»), к имени дописывается номер сертификата: <code>Иванов.cer</code>, <code>Иванов_99ff11.cer</code>. Повторно встреченный сертификат (например, корневой УЦ, который лежит в каждом .p7b) сохраняется один раз.<br><br>

<b>Флажок «Только сертификаты пользователя»</b> — не извлекать вышестоящие сертификаты удостоверяющих центров. УЦ определяется по расширению basicConstraints, затем по keyUsage и самоподписанности.<br><br>

<b>Флажок «Извлекать атрибутные сертификаты»</b> — в .p7b встречаются не только обычные X.509-сертификаты, но и атрибутные (AttributeCertificate) — например, в СОК ЮЛ ГосСУОК, совмещённом с атрибутным сертификатом. У них нет subject, поэтому по умолчанию они пропускаются. С этим флажком они тоже сохраняются, отдельно, в файлы <code>.acr</code>; ФИО/организация для имени файла берутся у связанного обычного сертификата того же владельца (по ссылке Holder.baseCertificateID), если он есть в том же .p7b.<br><br>

<b>Настройка через config.ini</b><br>
Все настройки хранятся в <code>config.ini</code> рядом с программой: папки, вариант имени, шаблон и режим извлечения. Файл можно править вручную — GUI его читает при запуске и перезаписывает при изменении настроек. Образец с описанием всех полей: <code>config.ini.example</code>.<br>

<pre>
[Paths]
InputFolder = C:\certs\in
OutputFolder = C:\certs\out

[Naming]
Preset = custom
Template = {surname}_{sok_id}

[Extract]
Certificates = user
</pre>

<b>Запуск без окна</b><br>
Параметр <code>ShowGui</code> в секции <code>[General]</code> отключает окно: программа запускается, сразу извлекает сертификаты по настройкам из <code>config.ini</code> и закрывается. Это режим для повседневной работы собранного .exe — окно нужно только для первоначальной настройки.<br>

<pre>
[General]
ShowGui = no
</pre>

Отчёт в этом режиме показывать негде, поэтому он пишется в <code>log_*.txt</code> рядом с программой. Код возврата: 0 — сертификаты сохранены, 1 — не сохранено ни одного, 2 — в <code>config.ini</code> не заданы папки.<br>
Ключи командной строки перекрывают <code>ShowGui</code> на один запуск:<br>
<code>main.exe --gui</code> — открыть окно, чтобы поменять настройки (нужно, если <code>ShowGui = no</code>);<br>
<code>main.exe --no-gui</code> — разово отработать без окна.<br>
То же самое переключается флажком «Запускать без окна» в самом окне.<br><br>

Обработку можно запустить и без GUI: <code>python p7b.py</code> — настройки берутся из того же файла.<br><br>


Инструкции по установке и запуску: <br>
Склонируйте репозиторий: git clone https://github.com/tores-kun/p7b_convert.git <br>
Перейдите в каталог проекта: cd p7b <br>
Установите необходимые зависимости: pip install -r requirements.txt <br>
Запустите приложение: python main.py <br>
Примечания: Приложение разработано с использованием Python и PyQt5.  <br>
Дополнительные настройки и функции могут быть добавлены в будущем. <br>
Благодарим за использование нашего приложения!<br><br>

-------------------------------------------------------------------------------------------
Extract Certificates from .p7b Files

A Python app using PyQt5 to extract certificates from .p7b files, saving them as .cer. Choose input/output folders and how the output files are named via a GUI.

Features:<br>
Extract and save certificates. Set input/output folders visually. <br>
Choose how certificate files are named: full name, surname, certificate serial, SOK ID (Subject Key Identifier), a combination of those, or a custom template such as <code>{surname}_{sok_id}</code>, with a live preview. Name clashes get the certificate serial appended; repeated certificates (a root CA present in every .p7b) are saved once. A checkbox limits extraction to end-entity certificates, skipping CA certificates.<br>
Everything is stored in <code>config.ini</code> (folders, naming preset, template, extraction mode) and can be edited by hand; <code>python p7b.py</code> runs the same settings without the GUI. See <code>config.ini.example</code>.<br>Set <code>ShowGui = no</code> under <code>[General]</code> to skip the window entirely: the program extracts straight away using <code>config.ini</code> and exits, writing its report to <code>log_*.txt</code> (exit code 0 saved, 1 nothing saved, 2 folders not configured). Handy for a packaged .exe, where the window is only needed for the initial setup. Run <code>main.exe --gui</code> to open the window again, or <code>--no-gui</code> for a one-off headless run.<br>

How to Use:<br>
Clone: git clone https://github.com/tores-kun/p7b_convert.git <br>
Navigate: cd p7b <br>
Install: pip install -r requirements.txt <br>
un: python main.py <br><br>

Notes:<br>
Developed in Python with PyQt5. Additional features may be added. Thank you for using our app!
