-- Создание таблицы для email-адресов
CREATE TABLE IF NOT EXISTS emails (
    email_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL
);

-- Создание таблицы для номеров телефонов
CREATE TABLE IF NOT EXISTS phones (
    phone_id SERIAL PRIMARY KEY,
    phone_number VARCHAR(255) UNIQUE NOT NULL
);

-- Вставка тестовых данных
INSERT INTO emails (email) VALUES
('test1@example.com'),
('test2@example.com');

INSERT INTO phones (phone_number) VALUES
('1234567890'),
('0987654321');

-- Создание пользователя для репликации
CREATE USER repl_user REPLICATION LOGIN CONNECTION LIMIT 5 ENCRYPTED PASSWORD 'maks';
CREATE ROLE replication;

GRANT REPLICATION TO repl_user;
