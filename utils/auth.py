USER_MIN_LENGTH = 3
USER_MAX_LENGTH = 32
USER_BOT_TEMPLATE_BLOCK = "RNDBOT"
PASS_MIN_LENGTH = 4

PASS_MAX_LENGTH = 32


def valid_username(username: str) -> bool:
    if (USER_MIN_LENGTH <= len(username) <= USER_MAX_LENGTH) is False:
        return False

    # Enforce alphanumeric usernames
    elif username.isalnum() is False:
        return False

    # Prevent users from making usernames that begin with the bot template
    elif (len(USER_BOT_TEMPLATE_BLOCK) <= len(username)) and (
        username[0 : len(USER_BOT_TEMPLATE_BLOCK)] == USER_BOT_TEMPLATE_BLOCK
    ):
        return False

    return True


def valid_password(password: str):
    if (PASS_MIN_LENGTH <= len(password) <= PASS_MAX_LENGTH) is False:
        return False

    # Enforce alphanumeric passwords
    elif password.isalnum() is False:
        return False

    return True
