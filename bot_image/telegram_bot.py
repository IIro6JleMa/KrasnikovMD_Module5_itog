import os
import re
import logging
import paramiko
import psycopg2
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG  # Установите уровень DEBUG для подробного логирования
)
logger = logging.getLogger(__name__)

class BotHandler:
    def __init__(self):
        # Инициализация бота и загрузка токена из переменных окружения
        self.token = os.environ.get('TOKEN')
        self.updater = Updater(token=self.token, use_context=True)
        self.dispatcher = self.updater.dispatcher

        # Загрузка параметров SSH для удаленного подключения
        self.rm_host = os.environ.get('RM_HOST')
        self.rm_port = int(os.environ.get('RM_PORT', '22'))
        self.rm_user = os.environ.get('RM_USER')
        self.rm_password = os.environ.get('RM_PASSWORD')

        # Загрузка параметров подключения к базе данных
        self.db_user = os.environ.get('DB_USER')
        self.db_password = os.environ.get('DB_PASSWORD')
        self.db_host = os.environ.get('DB_HOST')
        self.db_port = int(os.environ.get('DB_PORT', '5432'))
        self.db_database = os.environ.get('DB_DATABASE')

        # Инициализация клавиатур
        self.main_keyboard = ReplyKeyboardMarkup([
            [KeyboardButton('/help')],
            [KeyboardButton('/find_email'), KeyboardButton('/find_phone')],
            [KeyboardButton('/verify_password')],
            [KeyboardButton('/get_release'), KeyboardButton('/get_uname')],
            [KeyboardButton('/get_uptime'), KeyboardButton('/get_df')],
            [KeyboardButton('/get_free'), KeyboardButton('/get_mpstat')],
            [KeyboardButton('/get_w'), KeyboardButton('/get_auths')],
            [KeyboardButton('/get_critical'), KeyboardButton('/get_ps')],
            [KeyboardButton('/get_ss'), KeyboardButton('/get_services')],
            [KeyboardButton('/get_repl_logs')],
            [KeyboardButton('/get_emails'), KeyboardButton('/get_phone_numbers')],
            [KeyboardButton('/get_apt_list')]
        ], resize_keyboard=True)

        self.cancel_keyboard = ReplyKeyboardMarkup([
            [KeyboardButton('/cancel')]
        ], resize_keyboard=True)

        self.apt_keyboard = ReplyKeyboardMarkup([
            [KeyboardButton('/get_all_packages')],
            [KeyboardButton('/get_one_package')],
            [KeyboardButton('/cancel')]
        ], resize_keyboard=True)

        # Регистрация обработчиков команд
        self.register_handlers()

    def register_handlers(self):
        # Обработчики команд
        self.dispatcher.add_handler(CommandHandler('start', self.start_command))
        self.dispatcher.add_handler(CommandHandler('help', self.help_command))
        self.dispatcher.add_handler(CommandHandler('cancel', self.cancel_command))

        # Обработчики поиска информации в тексте
        find_email_conv = ConversationHandler(
            entry_points=[CommandHandler('find_email', self.find_email_command)],
            states={
                'find_email': [MessageHandler(Filters.text & ~Filters.command, self.find_email_handler)],
                'save_emails': [MessageHandler(Filters.text & ~Filters.command, self.save_emails_handler)],
            },
            fallbacks=[CommandHandler('cancel', self.cancel_command)]
        )

        find_phone_conv = ConversationHandler(
            entry_points=[CommandHandler('find_phone', self.find_phone_command)],
            states={
                'find_phone': [MessageHandler(Filters.text & ~Filters.command, self.find_phone_handler)],
                'save_phones': [MessageHandler(Filters.text & ~Filters.command, self.save_phones_handler)],
            },
            fallbacks=[CommandHandler('cancel', self.cancel_command)]
        )

        self.dispatcher.add_handler(find_email_conv)
        self.dispatcher.add_handler(find_phone_conv)

        # Обработчик проверки пароля
        verify_password_conv = ConversationHandler(
            entry_points=[CommandHandler('verify_password', self.verify_password_command)],
            states={
                'verify_password': [MessageHandler(Filters.text & ~Filters.command, self.verify_password_handler)],
            },
            fallbacks=[CommandHandler('cancel', self.cancel_command)]
        )
        self.dispatcher.add_handler(verify_password_conv)

        # Обработчики команд для мониторинга системы
        self.dispatcher.add_handler(CommandHandler('get_release', self.get_release_command))
        self.dispatcher.add_handler(CommandHandler('get_uname', self.get_uname_command))
        self.dispatcher.add_handler(CommandHandler('get_uptime', self.get_uptime_command))
        self.dispatcher.add_handler(CommandHandler('get_df', self.get_df_command))
        self.dispatcher.add_handler(CommandHandler('get_free', self.get_free_command))
        self.dispatcher.add_handler(CommandHandler('get_mpstat', self.get_mpstat_command))
        self.dispatcher.add_handler(CommandHandler('get_w', self.get_w_command))
        self.dispatcher.add_handler(CommandHandler('get_auths', self.get_auths_command))
        self.dispatcher.add_handler(CommandHandler('get_critical', self.get_critical_command))
        self.dispatcher.add_handler(CommandHandler('get_ps', self.get_ps_command))
        self.dispatcher.add_handler(CommandHandler('get_ss', self.get_ss_command))
        self.dispatcher.add_handler(CommandHandler('get_services', self.get_services_command))
        self.dispatcher.add_handler(CommandHandler('get_repl_logs', self.get_repl_logs_command))

        # Обработчики команд для работы с базой данных
        self.dispatcher.add_handler(CommandHandler('get_emails', self.get_emails_command))
        self.dispatcher.add_handler(CommandHandler('get_phone_numbers', self.get_phone_numbers_command))

        # Обработчики команд для работы с APT
        apt_list_conv = ConversationHandler(
            entry_points=[CommandHandler('get_apt_list', self.get_apt_list_command)],
            states={
                'apt_list': [MessageHandler(Filters.text & ~Filters.command, self.get_apt_list_handler)],
                'package_info': [MessageHandler(Filters.text & ~Filters.command, self.get_package_info_handler)],
            },
            fallbacks=[CommandHandler('cancel', self.cancel_command)]
        )
        self.dispatcher.add_handler(apt_list_conv)
        self.dispatcher.add_handler(CommandHandler('get_all_packages', self.get_all_packages_command))
        self.dispatcher.add_handler(CommandHandler('get_one_package', self.get_one_package_command))

        # Обработчик текстовых сообщений (эхо)
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.echo_message))

    # Команды бота

    def start_command(self, update: Update, context):
        update.message.reply_text('Здравствуйте! Я ваш бот-помощник.', reply_markup=self.main_keyboard)

    def help_command(self, update: Update, context):
        help_text = (
            "Доступные команды:\n"
            "1. Поиск информации в тексте:\n"
            " - Поиск email-адресов: /find_email\n"
            " - Поиск номеров телефонов: /find_phone\n"
            " - Проверка сложности пароля: /verify_password\n"
            "2. Информация о системе:\n"
            " - Версия ОС: /get_release\n"
            " - Информация о системе: /get_uname\n"
            " - Время работы системы: /get_uptime\n"
            " - Использование диска: /get_df\n"
            " - Использование памяти: /get_free\n"
            " - Статистика CPU: /get_mpstat\n"
            " - Активные пользователи: /get_w\n"
            " - Последние входы: /get_auths\n"
            " - Критические логи: /get_critical\n"
            " - Запущенные процессы: /get_ps\n"
            " - Открытые порты: /get_ss\n"
            " - Запущенные сервисы: /get_services\n"
            " - Логи репликации PostgreSQL: /get_repl_logs\n"
            "3. Работа с базой данных:\n"
            " - Получить email-адреса: /get_emails\n"
            " - Получить номера телефонов: /get_phone_numbers\n"
            "4. Работа с пакетами APT:\n"
            " - Список пакетов: /get_apt_list\n"
        )
        update.message.reply_text(help_text, reply_markup=self.main_keyboard)

    def cancel_command(self, update: Update, context):
        update.message.reply_text('Операция отменена.', reply_markup=self.main_keyboard)
        return ConversationHandler.END

    # Функции поиска информации в тексте

    def find_email_command(self, update: Update, context):
        update.message.reply_text('Введите текст для поиска email-адресов:', reply_markup=self.cancel_keyboard)
        return 'find_email'

    def find_email_handler(self, update: Update, context):
        text = update.message.text
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            context.user_data['emails'] = emails  # Сохраняем найденные emails
            email_list = '\n'.join([f"{i + 1}. {email}" for i, email in enumerate(emails)])
            update.message.reply_text(f'Найденные email-адреса:\n{email_list}', reply_markup=self.cancel_keyboard)
            update.message.reply_text('Хотите сохранить эти email-адреса в базу данных? (Да/Нет)', reply_markup=self.cancel_keyboard)
            return 'save_emails'
        else:
            update.message.reply_text('Email-адреса не найдены.', reply_markup=self.main_keyboard)
            return ConversationHandler.END

    def save_emails_handler(self, update: Update, context):
        response = update.message.text.strip().lower()
        if response == 'да':
            emails = context.user_data.get('emails', [])
            success = self.save_to_database('emails', emails)
            if success:
                update.message.reply_text('Email-адреса успешно сохранены.', reply_markup=self.main_keyboard)
            else:
                update.message.reply_text('Произошла ошибка при сохранении email-адресов.', reply_markup=self.main_keyboard)
        else:
            update.message.reply_text('Сохранение отменено.', reply_markup=self.main_keyboard)
        return ConversationHandler.END

    def find_phone_command(self, update: Update, context):
        update.message.reply_text('Введите текст для поиска номеров телефонов:', reply_markup=self.cancel_keyboard)
        return 'find_phone'

    def find_phone_handler(self, update: Update, context):
        text = update.message.text
        phone_pattern = r'(?:\+?\d{1,3})?\s*[\(\-]?\d{1,4}[\)\-]?\s*\d{1,4}(?:[\s\-]*\d{2,4}){1,3}'
        phones = re.findall(phone_pattern, text)
        phones = [phone.strip() for phone in phones if phone.strip()]
        if phones:
            context.user_data['phones'] = phones  # Сохраняем найденные номера
            phone_list = '\n'.join([f"{i + 1}. {phone}" for i, phone in enumerate(phones)])
            update.message.reply_text(f'Найденные номера телефонов:\n{phone_list}', reply_markup=self.cancel_keyboard)
            update.message.reply_text('Хотите сохранить эти номера телефонов в базу данных? (Да/Нет)', reply_markup=self.cancel_keyboard)
            return 'save_phones'
        else:
            update.message.reply_text('Телефонные номера не найдены.', reply_markup=self.main_keyboard)
            return ConversationHandler.END

    def save_phones_handler(self, update: Update, context):
        response = update.message.text.strip().lower()
        if response == 'да':
            phones = context.user_data.get('phones', [])
            success = self.save_to_database('phones', phones)
            if success:
                update.message.reply_text('Номера телефонов успешно сохранены.', reply_markup=self.main_keyboard)
            else:
                update.message.reply_text('Произошла ошибка при сохранении номеров телефонов.', reply_markup=self.main_keyboard)
        else:
            update.message.reply_text('Сохранение отменено.', reply_markup=self.main_keyboard)
        return ConversationHandler.END

    def verify_password_command(self, update: Update, context):
        update.message.reply_text('Введите пароль для проверки:', reply_markup=self.cancel_keyboard)
        return 'verify_password'

    def verify_password_handler(self, update: Update, context):
        password = update.message.text
        pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$'
        if re.match(pattern, password):
            update.message.reply_text('Пароль сложный.', reply_markup=self.main_keyboard)
        else:
            update.message.reply_text('Пароль простой.', reply_markup=self.main_keyboard)
        return ConversationHandler.END

    # Функции для мониторинга Linux-системы

    def get_host_info(self, command):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=self.rm_host, port=self.rm_port, username=self.rm_user, password=self.rm_password)

            stdin, stdout, stderr = client.exec_command(command, get_pty=True)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            client.close()

            logger.debug(f'Command output: {output}')
            logger.debug(f'Command error: {error}')

            if error:
                logger.error(f'Ошибка при выполнении команды на удаленном сервере: {error}')
                return None
            return output
        except Exception as e:
            logger.error(f'Ошибка при подключении по SSH: {e}')
            return None

    def send_host_info(self, update: Update, context, command, data=None):
        if not data:
            data = self.get_host_info(command)
        if not data:
            update.message.reply_text('Не удалось получить данные.', reply_markup=self.main_keyboard)
            return
        try:
            update.message.reply_text(data, reply_markup=self.main_keyboard)
        except Exception as e:
            max_length = 4096
            for i in range(0, len(data), max_length):
                update.message.reply_text(data[i:i+max_length])
            update.message.reply_text('Данные слишком длинные, вывод разделен.', reply_markup=self.main_keyboard)

    def get_release_command(self, update: Update, context):
        self.send_host_info(update, context, 'lsb_release -a')

    def get_uname_command(self, update: Update, context):
        self.send_host_info(update, context, 'uname -nmr')

    def get_uptime_command(self, update: Update, context):
        self.send_host_info(update, context, 'uptime')

    def get_df_command(self, update: Update, context):
        self.send_host_info(update, context, 'df -h')

    def get_free_command(self, update: Update, context):
        self.send_host_info(update, context, 'free -h')

    def get_mpstat_command(self, update: Update, context):
        self.send_host_info(update, context, 'mpstat -P ALL 1 1')

    def get_w_command(self, update: Update, context):
        self.send_host_info(update, context, 'w')

    def get_auths_command(self, update: Update, context):
        self.send_host_info(update, context, 'last -n 10')

    def get_critical_command(self, update: Update, context):
        data = self.get_host_info("journalctl -p crit -n 5 | grep -E '^[A-Za-z]{3} [0-9]{2}'")
        self.send_host_info(update, context, None, data)

    def get_ps_command(self, update: Update, context):
        self.send_host_info(update, context, 'ps aux')

    def get_ss_command(self, update: Update, context):
        self.send_host_info(update, context, 'ss -tuln')

    def get_services_command(self, update: Update, context):
        self.send_host_info(update, context, 'systemctl list-units --type=service --state=running')

    # Команда для получения логов репликации PostgreSQL

    def get_repl_logs_command(self, update: Update, context):
        try:
            container_name = 'postgres_db'  # Замените на фактическое имя или ID контейнера

            command = f'docker exec {container_name} sh -c "grep \'replication\' /var/log/postgresql/postgresql-*.log | tail -n 15"'
            data = self.get_host_info(command)
            if data:
                logger.info(f"Полученные логи:\n{data}")
                extracted_info = self.extract_replication_info(data)
                if extracted_info:
                    update.message.reply_text(f"Информация о репликации:\n{extracted_info}", reply_markup=self.main_keyboard)
                else:
                    update.message.reply_text('Не удалось извлечь информацию о репликации. Проверьте логи бота для подробностей.', reply_markup=self.main_keyboard)
                    logger.info(f"Извлеченная информация о репликации:\n{extracted_info}")
            else:
                update.message.reply_text('Логи репликации не найдены или отсутствуют.', reply_markup=self.main_keyboard)
        except Exception as e:
            logger.error(f'Ошибка при получении логов репликации: {e}')
            update.message.reply_text(f'Произошла ошибка при получении логов репликации.\nОшибка: {e}', reply_markup=self.main_keyboard)

    def extract_replication_info(self, log_data):
        pattern = r'''
            ^(?P<filename>/var/log/postgresql/postgresql-[^:]+):      # Имя файла
            (?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+
            (?P<timezone>[A-Z]+)\s+
            \[(?P<pid>\d+)\]\s+
            (?P<level>\w+):\s+
            (?P<message>.+)
        '''
        regex = re.compile(pattern, re.VERBOSE)
        lines = log_data.strip().split('\n')
        extracted_entries = []
        total_lines = len(lines)
        parsed_lines = 0

        for line in lines:
            match = regex.match(line)
            if match:
                filename = match.group('filename')
                timestamp = match.group('timestamp')
                timezone = match.group('timezone')
                pid = match.group('pid')
                level = match.group('level')
                message = match.group('message').strip()

                logger.debug(f"Обработанная строка лога: filename={filename}, timestamp={timestamp}, timezone={timezone}, pid={pid}, level={level}, message={message}")

                entry = (
                    f"Файл: {filename}\n"
                    f"Время: {timestamp} {timezone}\n"
                    f"PID: {pid}\n"
                    f"Уровень: {level}\n"
                    f"Сообщение: {message}\n"
                )
                extracted_entries.append(entry)
                parsed_lines += 1
            else:
                logger.warning(f"Не удалось распарсить строку: {line}")

        logger.info(f"Всего строк: {total_lines}, успешно распарсено: {parsed_lines}")

        if extracted_entries:
            return '\n\n'.join(extracted_entries)
        else:
            return None

    # Работа с базой данных

    def get_emails_command(self, update: Update, context):
        emails = self.fetch_from_database('emails')
        if emails:
            email_list = '\n'.join([f"{i + 1}. {email}" for i, email in enumerate(emails)])
            update.message.reply_text(f'Сохраненные email-адреса:\n{email_list}', reply_markup=self.main_keyboard)
        else:
            update.message.reply_text('Нет сохраненных email-адресов.', reply_markup=self.main_keyboard)

    def get_phone_numbers_command(self, update: Update, context):
        phones = self.fetch_from_database('phones')
        if phones:
            phone_list = '\n'.join([f"{i + 1}. {phone}" for i, phone in enumerate(phones)])
            update.message.reply_text(f'Сохраненные номера телефонов:\n{phone_list}', reply_markup=self.main_keyboard)
        else:
            update.message.reply_text('Нет сохраненных номеров телефонов.', reply_markup=self.main_keyboard)

    def save_to_database(self, table_name, data_list):
        try:
            connection = psycopg2.connect(
                user=self.db_user,
                password=self.db_password,
                host=self.db_host,
                port=self.db_port,
                database=self.db_database
            )
            cursor = connection.cursor()
            if table_name == 'emails':
                insert_query = 'INSERT INTO emails (email) VALUES (%s) ON CONFLICT DO NOTHING;'
            elif table_name == 'phones':
                insert_query = 'INSERT INTO phones (phone_number) VALUES (%s) ON CONFLICT DO NOTHING;'
            else:
                return False
            for item in data_list:
                cursor.execute(insert_query, (item,))
            connection.commit()
            cursor.close()
            connection.close()
            return True
        except Exception as e:
            logger.error(f'Ошибка при сохранении в базу данных: {e}')
            return False

    def fetch_from_database(self, table_name):
        try:
            connection = psycopg2.connect(
                user=self.db_user,
                password=self.db_password,
                host=self.db_host,
                port=self.db_port,
                database=self.db_database
            )
            cursor = connection.cursor()
            if table_name == 'emails':
                select_query = 'SELECT email FROM emails;'
            elif table_name == 'phones':
                select_query = 'SELECT phone_number FROM phones;'
            else:
                return []
            cursor.execute(select_query)
            records = cursor.fetchall()
            cursor.close()
            connection.close()
            return [record[0] for record in records]
        except Exception as e:
            logger.error(f'Ошибка при получении данных из базы данных: {e}')
            return []

    # Работа с пакетами APT

    def get_apt_list_command(self, update: Update, context):
        update.message.reply_text('Выберите опцию:', reply_markup=self.apt_keyboard)
        return 'apt_list'

    def get_apt_list_handler(self, update: Update, context):
        text = update.message.text
        if text == '/get_all_packages':
            self.get_all_packages_command(update, context)
            return ConversationHandler.END
        elif text == '/get_one_package':
            update.message.reply_text('Введите название пакета:', reply_markup=self.cancel_keyboard)
            return 'package_info'
        else:
            update.message.reply_text('Неверная опция.', reply_markup=self.cancel_keyboard)
            return 'apt_list'

    def get_all_packages_command(self, update: Update, context):
        data = self.get_host_info('dpkg -l')
        if data:
            packages = re.findall(r'^ii\s+([^\s]+)', data, re.MULTILINE)
            package_list = '\n'.join(packages)
            self.send_host_info(update, context, None, package_list)
        else:
            update.message.reply_text('Не удалось получить список пакетов.', reply_markup=self.main_keyboard)
        return ConversationHandler.END

    def get_one_package_command(self, update: Update, context):
        update.message.reply_text('Введите название пакета:', reply_markup=self.cancel_keyboard)
        return 'package_info'

    def get_package_info_handler(self, update: Update, context):
        package_name = update.message.text.strip()
        data = self.get_host_info(f'dpkg -s {package_name}')
        self.send_host_info(update, context, None, data)
        return ConversationHandler.END

    # Обработчик текстовых сообщений (эхо)

    def echo_message(self, update: Update, context):
        update.message.reply_text(update.message.text, reply_markup=self.main_keyboard)

    # Запуск бота

    def run(self):
        self.updater.start_polling()
        self.updater.idle()

if __name__ == '__main__':
    bot = BotHandler()
    bot.run()
