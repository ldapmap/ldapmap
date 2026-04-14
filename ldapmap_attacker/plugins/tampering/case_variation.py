import random


def tamper(payload: str) -> str:
    result = []
    for char in payload:
        if char.isalpha():
            result.append(char.lower() if random.random() > 0.5 else char.upper())
        else:
            result.append(char)
    return ''.join(result)
