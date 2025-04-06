from flask import Flask, request
import os
import utils
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

USER_ACCOUNT_LIMIT = int(os.getenv("USER_ACCOUNT_LIMIT", "5"))

MONGO_PARAMS = {
    "host": os.getenv("MONGO_HOST", "localhost"),
    "port": int(os.getenv("MONGO_PORT", "27017")),
    "user": os.getenv("MONGO_USER", "user"),
    "password": os.getenv("MONGO_PASSWORD", "password"),
}

MYSQL_PARAMS = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "user": os.getenv("MYSQL_USER", "user"),
    "port": int(os.getenv("MYSQL_PORT", "port")),
    "password": os.getenv("MYSQL_PASSWORD", "password"),
    "database": os.getenv("MYSQL_DATABASE", "dbname"),
}


@app.route("/create_account", methods=["POST"])
def create_account():
    success_message = "Account created."
    error_message = "Error creating account."

    mysql_conn = utils.get_connection(**MYSQL_PARAMS)
    if mysql_conn is None:
        return utils.message_maker(
            error_message, 500, {"error": "Failed to connect to the database."}
        )
    cursor = mysql_conn.cursor()
    try:
        # Validate request data
        data = request.json
        username = data.get("username")
        password = data.get("password")

        client_ip = request.headers.get("X-Real-IP", request.remote_addr)

        # Validate user credentials
        if utils.valid_username(username) is False:
            return utils.message_maker(
                error_message, 500, {"error": "Invalid username"}
            )
        elif utils.valid_password(password) is False:
            return utils.message_maker(
                error_message, 500, {"error": "Invalid password"}
            )

        salt, verifier = utils.calculate_srp6_verifier(username, password)

        # Verify that the username shares the requester's ip
        query = "SELECT username FROM account WHERE last_ip = %s"
        cursor.execute(query, (client_ip,))
        rows = cursor.fetchall()
        num_accounts = len([list(row) for row in rows])

        # Check if the user is at the account cap
        if USER_ACCOUNT_LIMIT <= num_accounts:
            return utils.message_maker(
                error_message,
                500,
                {
                    "error": f"Account limit reached - Accounts: {num_accounts}, Max: {USER_ACCOUNT_LIMIT}"
                },
            )

        # Insert the new account into the database
        query = "INSERT INTO account (username, salt, verifier, last_ip) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (username, salt, verifier, client_ip))
        mysql_conn.commit()
        return utils.message_maker(
            success_message, 201, {"message": "Account created successfully"}
        )
    except Exception as err:
        return utils.message_maker(error_message, 500, {"error": str(err)})
    finally:
        cursor.close()
        mysql_conn.close()


# Change password
@app.route("/change_password", methods=["POST"])
def change_password():
    success_message = "Password changed."
    error_message = "Error changing password."

    mysql_conn = utils.get_connection(**MYSQL_PARAMS)
    if mysql_conn is None:
        return utils.message_maker(
            error_message, 500, {"error": "Failed to connect to MySQL database."}
        )
    cursor = mysql_conn.cursor()
    try:
        client_ip = request.headers.get("X-Real-IP", request.remote_addr)
        # Validate request data
        data = request.json
        username = data.get("username")
        new_password = data.get("new_password")

        # Validate user credentials
        if not username:
            return utils.message_maker(
                error_message, 400, {"error": "Username is required."}
            )
        elif not utils.valid_password(new_password):
            return utils.message_maker(
                error_message, 400, {"error": "Invalid password."}
            )

        # Calculate new salt and verifier
        salt, verifier = utils.calculate_srp6_verifier(username, new_password)

        # Verify that the username shares the requester's ip
        query = "SELECT username FROM account WHERE last_ip = %s"
        cursor.execute(query, (client_ip,))
        rows = cursor.fetchall()
        accounts_list = [list(row) for row in rows]
        if username not in [x[0] for x in accounts_list]:
            return utils.message_maker(
                error_message,
                500,
                {"error": "Username provided does not match this IP."},
            )

        # Update the account with the new salt and verifier
        query = "UPDATE account SET salt = %s, verifier = %s WHERE username = %s"
        cursor.execute(query, (salt, verifier, username))
        mysql_conn.commit()
        return utils.message_maker(success_message, 200, {"message": "Success"})
    except Exception as err:
        return utils.message_maker(error_message, 500, {"error": str(err)})
    finally:
        cursor.close()
        mysql_conn.close()


@app.route("/list_accounts", methods=["POST"])
def list_accounts():
    success_message = "Accounts retrieved."
    error_message = "Error listing accounts."

    mysql_conn = utils.get_connection(**MYSQL_PARAMS)
    if mysql_conn is None:
        return utils.message_maker(
            error_message, 500, {"error": "Failed to connect to the database."}
        )
    cursor = mysql_conn.cursor()
    try:
        client_ip = request.headers.get("X-Real-IP", request.remote_addr)
        # Return a list of all accounts matching the request sender's ip
        query = "SELECT username FROM account WHERE last_ip = %s"
        cursor.execute(query, (client_ip,))
        rows = cursor.fetchall()
        accounts_list = [list(row) for row in rows]
        return utils.message_maker(
            success_message,
            201,
            {"message": f"Users registered to {client_ip}:{str(accounts_list)}"},
        )
    except Exception as err:
        return utils.message_maker(error_message, 500, {"error": str(err)})
    finally:
        cursor.close()
        mysql_conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
