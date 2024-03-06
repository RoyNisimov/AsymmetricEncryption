
class NeededValueIsNull(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)

class UnsafeEncryptionFunction(Exception):
    def __init__(self, func_name: str, msg: str):
        super().__init__(f"The function {func_name} is an unsafe function, error message:{msg}")