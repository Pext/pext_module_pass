from abc import ABC

class AbstractPasswordManager(ABC):
    def initialize(self) -> bool:
        pass

    def update(self) -> bool:
        pass

    def get_passwords(self) -> List[str]:
        pass

    def get_breached_passwords(self) -> List[str]:
        pass

    def get_password_string(self, str: name) -> str:
        pass

    def get_password_metadata(self, str: name) -> List[Dict[str, str]]:
        pass

    def get_password_otp(self, str: name) -> List[str]:
        pass

    def get_password_description(self, str: name) -> str:
        pass

    def set_password_string(self, str: name, str: value) -> bool:
        pass

    def set_password_metadata(self, str: name, List[Dict[str, str]]: value) -> bool:
        pass

    def set_password_otp(self, str: name, OrderedDict[str, str]: value) -> bool:
        pass


