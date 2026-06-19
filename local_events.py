"""本地事件占位模块，保留调用兼容，不进行任何网络上报。"""


def init(*args, **kwargs):
    return None


def set_tag(*args, **kwargs):
    return None


def set_user(*args, **kwargs):
    return None


def set_context(*args, **kwargs):
    return None


def capture_message(*args, **kwargs):
    return None


def capture_exception(*args, **kwargs):
    return "local-disabled"


def flush(*args, **kwargs):
    return None