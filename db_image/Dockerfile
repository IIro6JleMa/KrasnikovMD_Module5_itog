FROM postgres:15

# Передаем переменные окружения
ENV POSTGRES_DB=${DB_DATABASE}
ENV POSTGRES_USER=${DB_USER}
ENV POSTGRES_PASSWORD=${DB_PASSWORD}

RUN echo "host replication repl_user 0.0.0.0/0 trust" >> /var/lib/postgresql/data/pg_hba.conf && \
    echo "local   all             all                                     trust" >> /var/lib/postgresql/data/pg_hba.conf && \
    echo "host    all             all             0.0.0.0/0               trust" >> /var/lib/postgresql/data/pg_hba.conf && \
    echo "listen_addresses = '*'" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "wal_level = replica" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "archive_mode = on" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "archive_command = 'cp %p /oracle/pg_data/archive/%f'" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "max_wal_senders = 10" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "hot_standby = on" >> /var/lib/postgresql/data/postgresql.conf

# Копируем файлы баз данных в правильные папки конфигурации
ADD init.sql /docker-entrypoint-initdb.d/
ADD /data/pg_hba.conf /etc/postgresql/pg_hba.conf
ADD /data/postgresql.conf /etc/postgresql/postgresql.conf

# Настройка прав доступа на файлы конфигурации
RUN chown postgres:postgres /etc/postgresql/pg_hba.conf /etc/postgresql/postgresql.conf
