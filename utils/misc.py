from flask import jsonify

def message_maker(message: str, code: int, data: dict = {}):
    return jsonify({"message": message, "code": code, "data": data})
