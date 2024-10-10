FROM python:3.12-slim

# Устанавливаем необходимые зависимости для сборки проекта
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip install docker
# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем необходимые файлы
COPY requirements.txt ./
COPY . .

# Устанавливаем зависимости Python
RUN pip install --no-cache-dir -r requirements.txt

# Запускаем приложение
CMD ["python3", "telegram_bot.py"]
