# Сторонние компоненты

Клиент использует Qt for Python / PySide6-Essentials и shiboken6, aioquic,
cryptography, pyOpenSSL, certifi, cffi, attrs, service-identity, pylsqpack,
pycparser и typing_extensions. Точные версии и хеши находятся в
`desktop/requirements.lock`. PyInstaller используется для упаковки.

В нативном пакете тексты лицензий зависимостей сохраняются в `licenses/` и в
метаданных пакетов. Qt поставляется как отдельные динамические библиотеки.
Исходники сторонних проектов и условия лицензирования:

- Qt/PySide: https://code.qt.io/cgit/pyside/pyside-setup.git/
- Qt 6: https://download.qt.io/official_releases/qt/
- Qt licensing: https://doc.qt.io/qtforpython-6/licenses.html
- aioquic: https://github.com/aiortc/aioquic
- cryptography: https://github.com/pyca/cryptography
- PyInstaller: https://github.com/pyinstaller/pyinstaller
- Python: https://www.python.org/downloads/source/

Дизайн создан с применением unslop, Damir Sokolovsky (@heydamir), CC BY 4.0:
https://github.com/heydamir/unslop . Благодарность относится к используемому
дизайн-навыку; автор не заявляется автором или аудитором VPN-протокола.

Лицензия самого проекта не задана владельцем репозитория; RPM использует
`LicenseRef-NotSpecified`, не назначая проекту новую лицензию.
