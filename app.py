"""OPENAPI 3.0 / Тестовое задание"""

import os
import hashlib
from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './uploads'  # объявляем путь до папки с загрузками
ALLOWED_EXTENSIONS = ('txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif')  # список разрешенных форматов

app = Flask(__name__)  # Инициализируем приложение Flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # Указываем БД
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # ДОбавляем папку с фалами в настройки нашего приложения
db = SQLAlchemy(app)  # Объявляем переменную с БД нашего приложения


class Hashes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)  # Поле с индификатором пользователя
    title = db.Column(db.String(100), nullable=False)  # Поле с названием файла
    hash_md5 = db.Column(db.String(64), nullable=False)  # Поле с md5 хэш суммой
    hash_sha256 = db.Column(db.String(64), nullable=False)  # Поле с sha256 хэш суммой

    def __repr__(self):  # Перегружаем метом вывода названия нашего класса
        return '<hash %r>' % self.title


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Поле с индификатором пользователя пользователя
    apikey = db.Column(db.String(100), nullable=False)  # Поле с api ключом пользователя

    def __repr__(self):  # Перегружаем метом вывода названия нашего класса
        return '<User %r>' % self.id


def allowed_file(filename):
    """
    Проверяет расширение файла по списку разрешенных расширений
    :param filename:
    :return:
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.errorhandler(401)
def not_authorization(e):
    """Выводит 401 ошибку, если пользователь не указал 'X-Auth-User' заголовок или указанный api ключ не указан в БД"""
    return 'Не авторизирован', 401


@app.route('/file_hashes/<hash>', methods=['GET', 'DELETE'])
def get_or_delete_file_hashes(hash):
    """
    Принимает хэш сумму и параметр hash (md5 или sha256)
    При GET запросе возвращет список Json с данными о файлах с указанной хэш суммой
    При DELETE запросе удаляет запись из БД с указанной хэш суммой
    :param hash:
    :return: json or http response
    """
    if request.method == 'GET':
        res = []
        type_hash = request.args.get('hash')  # получаем значение параметра hash
        if type_hash == 'md5':  # если параметр hash равен md5 получаем все записи из бд с данной хэш суммой
            req_hash = Hashes.query.filter_by(hash_md5=hash).all()
        elif type_hash == 'sha256':  # если параметр hash равен sha256 получаем все записи из бд с данной хэш суммой
            req_hash = Hashes.query.filter_by(hash_sha256=hash).all()
        else:
            return "Ошибка. Неверные параметры"  # Если не указан или неправильно указан параметр hash
        if not req_hash:  # Если в БД не найдены файлы с указанным хэшем
            return 'Файлы с данным хэшем не найдены', 404
        for hash_file in req_hash:  # итерация по полученным записям в БД и добавление данных в список словарей
            res.append({
                "FileHash": {
                    "userId": hash_file.user_id,
                    "filename": hash_file.title,
                    "sha256": hash_file.hash_sha256,
                    "md5": hash_file.hash_md5
                }
            })
        return jsonify(res)  # возвращаем json
    else:  # Если метод DELETE
        user_apikey = request.headers.get('X-Auth-User')  # Получаем заголовок X-Auth-User
        req_user = Users.query.filter_by(apikey=user_apikey).first()  # Находим запись о пользователе в БД по API ключу
        if req_user is None:
            abort(401)  # Если пользователь не найден вызываем 401 ошибку
        user_id = req_user.id  # Получаем Айди пользователя из полученной записи в БД
        type_hash = request.args.get('hash')  # ПОлучаем значение параметра hash
        if type_hash == 'md5':  # если параметр hash равен md5 получаем запись из бд с данной хэш суммой либо 404 ошибку
            deleting_hash = Hashes.query.filter_by(hash_md5=hash, user_id=user_id).first_or_404(
                description='Файлы с данным хэшем не найдены')
        elif type_hash == 'sha256':
            # если параметр hash равен sha256 получаем запись из бд с данной хэш суммой либо 404 ошибку
            deleting_hash = Hashes.query.filter_by(hash_sha256=hash).first_or_404(
                description='Файлы с данным хэшем не найдены')
        else:
            return "Ошибка. Неверные параметры"  # Если не указан или неправильно указан параметр hash
        db.session.delete(deleting_hash)  # Удаляем запись из БД
        db.session.commit()  # Сохраняем изменения
        return "OK"


@app.route('/file_hashes/', methods=['POST'])
def post_file_hashes():
    """
    Получает файл из запроса,
    загружает его в папку uploads,
    вычисляет его хэш сумму(md5 и sha256),
    вносит данные в БД
    """
    user_apikey = request.headers.get('X-Auth-User')  # Получаем заголовок X-Auth-User
    req_user = Users.query.filter_by(apikey=user_apikey).first()  # Находим запись о пользователе в БД по API ключу
    if req_user is None:
        abort(401)  # Если пользователь не найден вызываем 401 ошибку
    content = request.headers.get('Content-Type')  # Получаем данные из заголовка Content-Type
    if "multipart/form-data" not in content:  # Если Content-Type не содержит multipart/form-data выводим ошибку
        return 'Неверный Content-Type'
    try:
        file = request.files['file']  # Получаем файл из запроса
    except KeyError:  # Если некоректно составлен запрос
        return 'Некоректный запрос'
    if allowed_file(file.filename):  # Если файл прошел проверку и имеет разрешеное расширение
        filename = secure_filename(file.filename)  # убираем из имени файла символы которые могут навредить приложению
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Сохраняем файл в папке uploads
        file_for_hash = open(f'uploads/{filename}', 'rb')  # Открываем полученный файл
        hash_object_sha256 = hashlib.sha256(file_for_hash.read())  # Вычисляем sha256 хэш сумму
        file_for_hash = open(f'uploads/{filename}', 'rb')  # Открываем полученный файл
        hash_object_md5 = hashlib.md5(file_for_hash.read())  # Вычисляем md5 хэш сумму
        # Проверяем существует ли у пользователя такой файл
        hash_already_add = Hashes.query.filter_by(hash_md5=hash_object_md5.hexdigest(),
                                                  user_id=req_user).first()
        if hash_already_add is None:  # Если такого файла нет
            h = Hashes(user_id=req_user, title=filename, hash_md5=hash_object_md5.hexdigest(),
                       hash_sha256=hash_object_sha256.hexdigest())  # Создаем экземпляр Модели Hashes
            db.session.add(h)  # Добавляем его в БД
            db.session.commit()  # Сохраняем изменения
        return 'OK', 201
    else:
        return 'Недопустимый формат'  # Если файл имеет расширение не указанное в разрешенных


if __name__ == '__main__':
    app.run(port="3000")  # Запускаем сервер на 3000 порту
