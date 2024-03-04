import datetime
from functools import wraps

import os
import jwt
import jwt_helper
import psycopg2
import re
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from config import host, db_name, user, password, SECRET_KEY

SELECT_INVESTOR = """SELECT * FROM investors;"""

app = Flask(__name__)

app.config["SECRET_KEY"] = SECRET_KEY

try:
    conn = psycopg2.connect(
        host=host,
        user=user,
        password=password,
        database=db_name
    )
    conn.autocommit = True


    @app.get('/api/ping')
    def ping():
        return jsonify({"status": "ok"}), 200


    def update_user_jwt(jw_token, investor_id):
        with conn.cursor() as cursor:
            cursor.execute("UPDATE investors SET jwt = %s WHERE id = %s RETURNING jwt;", (jw_token, investor_id))
            result = cursor.fetchone()
        return result


    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None

            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split(" ")[1]

            if not token:
                return jsonify({'reason': 'Token is missing!'}), 401

            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user_id = data['id']

                with conn.cursor() as cursor:
                    cursor.execute("SELECT jwt FROM investors WHERE id = %s", (current_user_id,))
                    user_last_token = cursor.fetchone()
                    if token != user_last_token[0]:
                        return jsonify({'reason': 'Token is invalid!'}), 401
            except Exception as ex:
                print(f"Exception: {ex}")
                return jsonify({'reason': 'Token is invalid!'}), 401

            return f(current_user_id, *args, **kwargs)

        return decorated


    @app.get('/api/countries')
    def get_countries():
        with conn.cursor() as cursor:
            region_filter = request.args.get('region')
            if region_filter:
                cursor.execute("SELECT * FROM countries WHERE region = %s ORDER BY alpha2", (region_filter,))
            elif region_filter is None:
                cursor.execute("SELECT * FROM countries ORDER BY alpha2")
            else:
                return jsonify({'reason': "The input request format does not match the format or incorrect values were passed"}), 400
            countries = cursor.fetchall()
            result = [{'name': country[1], 'alpha2': country[2], 'alpha3': country[3], 'region': country[4]} for country
                      in countries]
        return jsonify(result), 200


    @app.get('/api/countries/<alpha2>')
    def get_country(alpha2):
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM countries WHERE alpha2 = %s;", (alpha2,))
            country = cursor.fetchone()
            if country:
                result = {'name': country[1], 'alpha2': country[2], 'alpha3': country[3], 'region': country[4]}
                return jsonify(result), 200
            else:
                return jsonify({'reason': "The country with the specified code was not found"}), 404


    @app.get("/api/investors")
    def get_investor():
        with conn.cursor() as cursor:
            cursor.execute(SELECT_INVESTOR)
            investors = cursor.fetchall()
            result = [{'id': investor[0], 'login': investor[1], 'email': investor[2]} for investor in investors]
        return jsonify(result)


    def validate_pass(password):
        if 6 > len(password) > 100:
            return False
        if not re.search(r'[a-z]', password) or not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        if password is None:
            return False

        return True


    def validate_login(login):
        if len(login) > 30:
            return False
        if login is None:
            return False
        pattern = r'[a-zA-Z0-9-]+'
        if re.fullmatch(pattern, login) is None:
            return False

        return True


    def validate_email(email):
        if 1 > len(email) > 50:
            return False
        if email is None:
            return False

        return True


    def validate_phone(phone):
        if phone:
            if len(phone) > 20:
                return False
            pattern = r'\+[\d]+'
            if re.fullmatch(pattern, phone) is None:
                return False
        return True


    def validate_img(img):
        if img:
            if 1 > len(img) > 200:
                return False
        return True


    def validate_country_code(cc):
        with conn.cursor() as cursor:
            cursor.execute("SELECT alpha2 FROM countries WHERE alpha2 = %s", (cc,))
            res = cursor.fetchone()
            if res is None:
                return False
        return True


    # Добавление нового инвестора
    @app.post('/api/auth/register')
    def register():
        data = request.get_json()
        login = data['login']
        email = data['email']
        password = data['password']
        country_code = data['countryCode']
        is_public = data['isPublic']

        try:
            phone = data['phone']
        except KeyError:
            phone = None

        try:
            img = data['image']
        except KeyError:
            img = None

        with conn.cursor() as cursor:
            if validate_country_code(country_code) is False or is_public is None or validate_pass(password) is False or validate_email(email) is False or validate_login(login) is False or validate_phone(phone) is False or validate_img(img) is False:
                return jsonify({'reason':"Registration data does not comply with the expected format and requirements."}), 400

            cursor.execute("SELECT id FROM investors WHERE login = %s OR email = %s OR phone = %s;",
                           (login, email, phone))
            existing_id = cursor.fetchone()
            if existing_id:
                return jsonify({"reason": "Data already exist"}), 409
            else:
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO investors (login, email, password, country_code, is_public, phone, image) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *;",
                    (login, email, hashed_password, country_code, is_public, phone, img))
                investor = cursor.fetchone()
                return jsonify(profile=get_investor_profile(investor)), 201


    @app.post('/api/auth/sign-in')
    def sign_in():
        data = request.get_json()
        login = data['login']
        password = data['password']
        with conn.cursor() as cursor:
            cursor.execute("""SELECT id, password FROM investors WHERE login = %s""", (login,))
            res = cursor.fetchone()
            if res is not None:
                auth_id, hash_pass = res
                if auth_id and check_password_hash(hash_pass, password):
                    token = jwt_helper.get_new_jwt(auth_id)
                    update_user_jwt(token, auth_id)
                    return jsonify({'token': token}), 200
                else:
                    return jsonify({'reason': 'Incorrect data'}), 401
            else:
                return jsonify({'reason': 'Incorrect data'}), 401


    @app.route('/api/me/profile', methods=['GET', 'PATCH'])
    @token_required
    def profile(current_user_id):
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM investors WHERE id = %s", (current_user_id,))
            investor = cursor.fetchone()
            if not investor:
                return jsonify({'reason': 'Investor not found'}), 404

            country_code = investor[5]
            is_public = investor[6]
            phone = investor[7]
            image = investor[8]

            if request.method == 'PATCH':
                data = request.get_json()

                if 'phone' in data:
                    if data['phone'] != phone:
                        cursor.execute("SELECT id FROM investors WHERE phone = %s;", (data['phone'],))
                        res = cursor.fetchone()
                        if res is not None:
                            return jsonify({'reason':"Phone already exist"}), 409

                if validate_country_code(data.get('countryCode', country_code)) and validate_phone(
                        data.get('phone', phone)) and validate_img(data.get('image', image)):
                    cursor.execute(
                        "UPDATE investors SET country_code = %s, is_public = %s, phone = %s, image = %s WHERE id = %s RETURNING *;",
                        (data.get('countryCode', country_code), data.get('isPublic', is_public),
                         data.get('phone', phone), data.get('image', image), current_user_id))
                    investor = cursor.fetchone()
                else:
                    return jsonify({'reason':"The data does not conform to the expected format and requirements."}), 400

        return jsonify(get_investor_profile(investor)), 200


    def get_investor_profile(investor):
        if investor[8] and investor[7]:
            investor_data = {'login': investor[1], 'email': investor[2], 'countryCode': investor[5],
                                         'isPublic': investor[6], 'phone': investor[7], 'image': investor[8]}
        if investor[7] and investor[8] is None:
            investor_data = {'login': investor[1], 'email': investor[2], 'countryCode': investor[5],
                                         'isPublic': investor[6], 'phone': investor[7]}
        if investor[8] and investor[7] is None:
            investor_data = {'login': investor[1], 'email': investor[2], 'countryCode': investor[5],
                                         'isPublic': investor[6], 'image': investor[8]}
        if investor[8] is None and investor[7] is None:
            investor_data = {'login': investor[1], 'email': investor[2], 'countryCode': investor[5]}

        return investor_data


    @app.get('/api/profiles/<login>')
    @token_required
    def get_profile(current_user_id, login):
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM investors WHERE login = %s", (login,))
            investor = cursor.fetchone()

            if not investor:
                return jsonify({'reason': 'Profile could not be retrieved'}), 403

            if current_user_id == investor[0]:
                return jsonify(get_investor_profile(investor)), 200

            if investor[6] is True:
                return jsonify(get_investor_profile(investor)), 200
            elif investor[6] is False:
                cursor.execute("SELECT friend_login FROM friends WHERE user_id = %s", (current_user_id,))
                result = cursor.fetchall()
                friend_logins = [item[0] for item in result if isinstance(item, tuple)]
                if investor[1] in friend_logins:
                    return jsonify(get_investor_profile(investor)), 200
                else:
                    return jsonify({'reason': 'Profile could not be retrieved'}), 403
            else:
                return jsonify({'reason': 'Profile could not be retrieved'}), 403


    @app.route('/api/me/updatePassword', methods=['GET', 'PATCH'])
    @token_required
    def update_password(current_user_id):
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM investors WHERE id = %s", (current_user_id,))
            investor = cursor.fetchone()
            if not investor:
                return jsonify({'reason': 'Investor not found'}), 404

            password = investor[3]
            if request.method == 'PATCH':
                data = request.get_json()
                old_password = data['oldPassword']
                new_password = data['newPassword']
                if check_password_hash(password, old_password):
                    if validate_pass(new_password) is False:
                        return jsonify({'reason': "The new password does not meet security requirements"}), 400

                    hashed_password = generate_password_hash(new_password)
                    cursor.execute("UPDATE investors SET password = %s WHERE id = %s RETURNING password;",
                                   (hashed_password, current_user_id))

                    token = jwt_helper.get_new_jwt(current_user_id)
                    update_user_jwt(token, current_user_id)
                    return jsonify({'status': 'ok'}), 200
                else:
                    return jsonify({'reason': 'The specified password does not match the actual one'}), 403


    @app.post('/api/friends/add')
    @token_required
    def add_friend(current_user_id):
        data = request.get_json()
        friend_login = data['login']
        user_id = current_user_id
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM investors WHERE login = %s;", (friend_login,))
            result = cursor.fetchone()
            if result is not None:
                if result[0] == user_id:
                    return jsonify({'status': 'ok'}), 200

                if result[0] != user_id:
                    rfc3339_time = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

                    cursor.execute(
                        "INSERT INTO friends (user_id, friend_login, added_at) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                        (user_id, friend_login, rfc3339_time))
                    return jsonify({'status': 'ok'}), 200
            else:
                return jsonify({"reason": "The user with the specified login was not found"}), 404


    @app.post('/api/friends/remove')
    @token_required
    def remove_friend(current_user_id):
        data = request.get_json()
        friend_login = data['login']
        user_id = current_user_id
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM friends WHERE user_id = %s AND friend_login = %s;",
                           # cursor.execute("DELETE FROM friends WHERE user_id = %s AND friend_id = %s RETURNING friend_id;",
                           (user_id, friend_login))
            return jsonify({"status": "ok"}), 200


    def check_limit(limit, default=5):
        if 0 > limit > 50:
            return default
        return limit


    def check_offset(offset, default=0):
        if 0 > offset:
            return default
        return offset


    @app.get('/api/friends')
    @token_required
    def get_friends(current_user_id):
        user_id = current_user_id
        offset = check_offset(int(request.args.get('offset', 0)))
        limit = check_limit(int(request.args.get('limit', 5)))
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT friend_login, added_at FROM friends WHERE user_id = %s ORDER BY added_at DESC OFFSET %s LIMIT %s",
                (user_id, offset, limit))
            friends = cursor.fetchall()
            friends = [{'friend_login': friend[0], 'addedAt': friend[1]} for friend in friends]
            return jsonify(friends), 200


    @app.post('/api/posts/new')
    @token_required
    def create_post(current_user_id):
        data = request.get_json()
        content = data['content']
        tags = data['tags']

        with conn.cursor() as cursor:
            cursor.execute("SELECT login FROM investors WHERE id = %s", (current_user_id,))
            login = cursor.fetchone()[0]

            rfc3339_time = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

            cursor.execute(
                "INSERT INTO posts (content, author, tags, created_at, likes_count, dislikes_count) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (content, login, tags, rfc3339_time, 0, 0))

            post = cursor.fetchone()
            result = {'id': post[0], 'content': post[1], 'author': post[2], 'tags': post[3],
                      'createdAt': post[4], 'likesCount': post[5], 'dislikesCount': post[6]}
            return jsonify(result), 200


    @app.get('/api/posts/<postId>')
    @token_required
    def get_post_by_id(current_user_id, postId):
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM posts WHERE id = %s", (postId,))
            post = cursor.fetchone()
            result = {'id': post[0], 'content': post[1], 'author': post[2], 'tags': post[3],
                      'createdAt': post[4], 'likesCount': post[5], 'dislikesCount': post[6]}

            cursor.execute("SELECT * FROM investors WHERE login = %s", (post[2],))
            investor = cursor.fetchone()
            if not investor:
                return jsonify({'reason': 'The specified post was not found or cannot be accessed.'}), 404

            check_public(investor, 'The specified post was not found or cannot be accessed.', current_user_id, result,
                         cursor)


    @app.get('/api/posts/<postId>/<reaction>')
    @token_required
    def react(current_user_id, postId, reaction):
        with conn.cursor() as cursor:
            cursor.execute("""INSERT INTO reactions (user_id, post_id, reaction_type) VALUES (%s, %s, %s)
                            ON CONFLICT (user_id, post_id) DO UPDATE SET reaction_type = %s;""",
                           (current_user_id, postId, reaction, reaction))

            cursor.execute("SELECT COUNT(*) FROM reactions WHERE reaction_type = %s AND post_id = %s", ('like', postId))
            likes_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM reactions WHERE reaction_type = %s AND post_id = %s",
                           ('dislike', postId))
            dislikes_count = cursor.fetchone()[0]

            cursor.execute("UPDATE posts SET likes_count = %s, dislikes_count = %s WHERE id = %s RETURNING * ;",
                           (likes_count, dislikes_count, postId))
            post = cursor.fetchone()

            result = {'id': post[0], 'content': post[1], 'author': post[2], 'tags': post[3],
                      'createdAt': post[4], 'likesCount': post[5], 'dislikesCount': post[6]}

            cursor.execute("SELECT * FROM investors WHERE login = %s", (post[2],))
            investor = cursor.fetchone()
            if not investor:
                return jsonify({'reason': 'The specified post was not found or cannot be accessed.'}), 404

            return check_public(investor, 'The specified post was not found or cannot be accessed.', current_user_id,
                                result, cursor)


    def check_public(investor, exc, user_id, result_for_return, cursor):
        if investor[0] == user_id:
            return jsonify(result_for_return), 200
        if investor[6] is True:
            return jsonify(result_for_return), 200
        elif investor[6] is False:
            cursor.execute("SELECT friend_login FROM friends WHERE user_id = %s", (user_id,))
            res = cursor.fetchall()
            friend_logins = [item[0] for item in res if isinstance(item, tuple)]
            if investor[1] in friend_logins:
                return jsonify(result_for_return), 200
            else:
                return jsonify({'reason': exc}), 404
        else:
            return jsonify({'reason': exc}), 404


    def get_posts(posts):
        result = [{'id': post[0], 'content': post[1], 'author': post[2], 'tags': post[3],
                   'createdAt': post[4], 'likesCount': post[5], 'dislikesCount': post[6]} for post in posts]
        return result


    @app.get('/api/posts/feed/my')
    @token_required
    def watch_posts(current_user_id):
        offset = check_offset(int(request.args.get('offset', 0)))
        limit = check_limit(int(request.args.get('limit', 5)))
        with conn.cursor() as cursor:
            cursor.execute("SELECT login FROM investors WHERE id = %s", (current_user_id,))
            login = cursor.fetchone()[0]

            cursor.execute("SELECT * FROM posts WHERE author = %s ORDER BY created_at DESC OFFSET %s LIMIT %s",
                           (login, offset, limit))
            posts = cursor.fetchall()
            result = get_posts(posts)
            return jsonify(result), 200


    @app.get('/api/posts/feed/<login>')
    @token_required
    def watch_posts_by_id(current_user_id, login):
        offset = check_offset(int(request.args.get('offset', 0)))
        limit = check_limit(int(request.args.get('limit', 5)))
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM posts WHERE author = %s ORDER BY created_at DESC OFFSET %s LIMIT %s",
                           (login, offset, limit))
            posts = cursor.fetchall()
            result = get_posts(posts)

            cursor.execute("SELECT * FROM investors WHERE login = %s", (login,))
            investor = cursor.fetchone()
            if not investor:
                return jsonify({'reason': 'The user was not found or there is no access to it.'}), 404

            check_public(investor, 'The user was not found or there is no access to it.', current_user_id, result,
                         cursor)


except Exception as _ex:
    print(f"Exception: {_ex}")

if __name__ == '__main__':
    app.run(host=os.environ['SERVER_ADDRESS'], port=int(os.environ['SERVER_PORT']), debug=True)
