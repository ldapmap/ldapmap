class LDAPMapError(Exception):
    pass


class PluginError(LDAPMapError):
    pass


class RequestError(LDAPMapError):
    pass


class DetectionError(LDAPMapError):
    pass
