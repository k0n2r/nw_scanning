#!/bin/bash

# Проверка на наличие утилиты nmap
if ! command -v nmap &>/dev/null; then
    echo "Ошибка: утилита nmap не установлена. Установите nmap и повторите попытку."
    exit 1
fi

# Запрос IP-адреса или подсети
echo "Введите IP-адрес или подсеть для сканирования (например, 192.168.1.0/24):"
read target

# Проверка, что IP-адрес или подсеть были введены
if [ -z "$target" ]; then
    echo "Ошибка: необходимо указать IP-адрес или подсеть."
    exit 1
fi

# Устанавливаем директорию для вывода результатов
OUTPUT_DIR="Результат_nw_scanning"
mkdir -p "$OUTPUT_DIR"

# Задаем формат для имени файла вывода
TIMESTAMP=$(date +"%d.%m.%Y_%H.%M" -d '3 hours')  # Московское время (+3 часа)
OUTPUT_FILE="${OUTPUT_DIR}/scan_nw_${TIMESTAMP}.txt"

# Функция для сканирования подсети
scan_subnet() {
    local subnet="$1"
    # Получаем диапазон хостов для подсети, используя nmap
    echo "Сканируем все хосты в подсети $subnet..."
    active_hosts=$(nmap -sn "$subnet" | grep "Nmap scan report for" | awk '{print $5}')
    
    if [ -z "$active_hosts" ]; then
        echo "Нет активных хостов в сети $subnet."
        exit 0
    fi
    
    echo "Найденные активные хосты:"
    echo "$active_hosts"
    
    # Запрос на продолжение сканирования
    echo "Сканировать найденные хосты? (y/n)"
    read response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Сканирование завершено. Результаты записаны в файл: $OUTPUT_FILE"
        exit 0
    fi
    
    # Сканируем каждый активный хост
    for host in $active_hosts; do
        echo "Сканируем хост $host..."
        nmap -Pn --disable-arp-ping --max-retries 5 --host-timeout 60s -sS -T2 \
        -p 21,22,23,25,53,80,110,135,139,143,443,445,3389,3306,8080,8443 \
        --script vuln --reason "$host" -oN "$OUTPUT_FILE"
    done
}

# Проверка, является ли введённый адрес подсетью (содержит "/")
if [[ "$target" == *"/"* ]]; then
    # Сканируем всю подсеть
    echo "Сканируется подсеть $target..."
    scan_subnet "$target"
else
    # Если это одиночный IP-адрес, сканируем только его
    echo "Сканируется хост $target..."
    nmap -Pn --disable-arp-ping --max-retries 5 --host-timeout 60s -sS -T2 \
    -p 21,22,23,25,53,80,110,135,139,143,443,445,3389,3306,8080,8443 \
    --script vuln --reason "$target" -oN "$OUTPUT_FILE"
fi

# Если это одиночный IP, запускаем ncat для связи
if [[ "$target" != *"/"* ]]; then
    echo "Запуск ncat на хосте $target..."
    ncat -nv --source-port 53 "$target" 50000 >> "$OUTPUT_FILE" 2>&1
fi

echo "Сканирование завершено. Результаты записаны в файл: $OUTPUT_FILE"

# Функция для анализа и форматирования результатов сканирования
parse_results() {
    local file="$1"                 # Путь к файлу с результатами сканирования
    local found_devices=false       # Флаг для отслеживания найденных устройств
    local filtered_ports=()         # Массив для хранения фильтрованных портов
    local open_ports=()             # Массив для хранения открытых портов
    local closed_ports=()           # Массив для хранения закрытых портов

    echo "--- Основные результаты сканирования ---"
    
    # Чтение результатов построчно
    while IFS= read -r line; do
        # Поиск IP-адреса устройства
        if [[ $line == *"Nmap scan report for"* ]]; then
            # Печать пустой строки, если устройство найдено ранее
            if [[ $found_devices == true ]]; then
                echo
            fi
            ip=$(echo "$line" | awk '{print $NF}')   # Извлечение IP-адреса
            echo -e "IP: $ip"                        # Вывод IP-адреса
            found_devices=true                       # Обновление флага устройства
        fi

        # Поиск информации об операционной системе
        if [[ $line == *"OS details:"* ]]; then
            os_info=$(echo "$line" | sed 's/OS details: //') # Извлечение ОС
            echo -e "  Операционная система: ${os_info:-Неизвестно}"  # Вывод ОС или "Неизвестно"
        fi

        # Поиск открытых портов
        if [[ $line == *"/tcp open"* ]]; then
            port=$(echo "$line" | awk '{print $1}')       # Извлечение порта
            service=$(echo "$line" | awk '{print $3}')     # Извлечение сервиса
            version=$(echo "$line" | cut -d ' ' -f 4-)     # Извлечение версии сервиса
            open_ports+=("$port")                         # Добавление открытого порта в массив
            echo -e "  Открытый порт: $port ($service) - ${version:-Неизвестно}"  # Вывод информации о порте
        fi

        # Поиск закрытых портов
        if [[ $line == *"/tcp closed"* ]]; then
            port=$(echo "$line" | awk '{print $1}')       # Извлечение порта
            closed_ports+=("$port")                       # Добавление закрытого порта в массив
            echo -e "  Закрытый порт: $port"              # Вывод информации о закрытом порте
        fi

        # Поиск фильтрованных портов
        if [[ $line == *"/tcp filtered"* ]]; then
            port=$(echo "$line" | awk '{print $1}' | cut -d '/' -f 1)  # Извлечение порта
            filtered_ports+=("$port")                                  # Добавление в массив фильтрованных портов
        fi
    done < "$file"

    # Вывод всех фильтрованных портов, если они найдены
    if [[ ${#filtered_ports[@]} -gt 0 ]]; then
        echo -e "  Фильтрованные порты: ${filtered_ports[*]}"
    fi

    # Вывод всех открытых портов, если они найдены
    if [[ ${#open_ports[@]} -gt 0 ]]; then
        echo -e "  Открытые порты: ${open_ports[*]}"
    fi

    # Вывод всех закрытых портов, если они найдены
    if [[ ${#closed_ports[@]} -gt 0 ]]; then
        echo -e "  Закрытые порты: ${closed_ports[*]}"
    fi
}

# Вызов функции для форматирования и анализа результатов
parse_results "$OUTPUT_FILE"
