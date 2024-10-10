# db_repl_image Dockerfile
FROM postgres:15

# Передаем переменные окружения
ENV POSTGRES_DB=${DB_DATABASE}
ENV POSTGRES_USER=${DB_USER}
ENV POSTGRES_PASSWORD=${DB_REPL_PASSWORD}

# Копируем файлы для репликации
COPY ./data_repl/postgresql.conf /var/lib/postgresql/data/postgresql.conf
COPY ./data_repl/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf
