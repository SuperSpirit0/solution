import jwt
from config import SECRET_KEY
from datetime import datetime, timedelta


def get_new_jwt(id):
    expiration_time = datetime.utcnow() + timedelta(hours=24)

    # Create the payload for the JWT
    payload = {
        "id": id,
        "exp": expiration_time
    }

    # Encode the JWT
    jw_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return jw_token
