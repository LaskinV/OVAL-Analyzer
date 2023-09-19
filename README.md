# OVAL-Analyzer
В этом репозитории представлен анализ файла OVAL, предоставленного RHEL, с особым вниманием к первым трем уязвимостям (патчам). Целью является понимание структуры, логики и компонентов формата OVAL и предложение улучшений.

# Содержание
Введение
Анализированные компоненты
Обзор критериев
Упрощение формата
Использование


# Введение
Open Vulnerability and Assessment Language (OVAL) — это общественная инициатива по стандартизации методов оценки и отчетности о состоянии компьютерных систем. Этот анализ направлен на понимание ключевых компонентов и логики файла OVAL, предоставленного RHEL для их версии 8.

# Анализированные компоненты
Основные компоненты файла OVAL, которые были проанализированы:

Определения (Definitions): Описания конкретных уязвимостей, конфигураций или аспектов безопасности системы, подлежащих проверке.
Метаданные (Metadata): Дополнительная информация о каждом определении, такая как описания, ссылки и другие детали.
Критерии (Criteria): Логические условия, используемые для определения соответствия системы определениям.
Тесты (Tests): Указания о том, какие аспекты системы следует проверять и как их проверять.

# Обзор критериев
При рассмотрении кажется, что все критерии имеют свою роль. Однако некоторые критерии могут показаться избыточными. Подробный обзор этих критериев представлен в файле Решение_Задание_для_инженера_аналитика_v2.

# Упрощение формата
Формат OVAL содержит множество деталей, которые могут быть избыточными для некоторых пользователей. Предлагается упрощенный формат, который фокусируется на:

- Объединении блоков информации
- Упрощении структуры критериев
- Уменьшении избыточных данных
