## Базовый образ для сборки
FROM python:3.9.10-slim

# Указываем рабочую директорию
WORKDIR /usr/src/app

# Запрещаем Python писать файлы .pyc на диск
ENV PYTHONDONTWRITEBYTECODE 1
# Запрещает Python буферизовать stdout и stderr
ENV PYTHONUNBUFFERED 1

# Копируем проект
COPY . .

# Установка зависимостей проекта
RUN pip install -r requirements.txt --no-cache-dir
