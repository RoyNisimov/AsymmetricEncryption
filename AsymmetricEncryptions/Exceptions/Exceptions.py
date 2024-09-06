
class NeededValueIsNull(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)

class UnsafeEncryptionFunction(Exception):
    def __init__(self, func_name: str, msg: str):
        super().__init__(f"The function {func_name} is an unsafe function, error message:{msg}")

class MACError(Exception):

    def __init__(self, msg: str, mac_type: str = "HMAC"):
        super().__init__(f"A MAC of type {mac_type} is not matching. Error message: {msg}")

class DeprecatedClass(Exception):

    def __init__(self):
        super().__init__(f"The Function or Class is deprecated and is to not be used until fixed!")

    @staticmethod
    def DeprecatedFunc(*args, **kwargs) -> callable:
        def wrapper(*args, **kwargs) -> callable:
            raise DeprecatedClass()
        return wrapper
