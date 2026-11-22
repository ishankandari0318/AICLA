"""One error type for every problem a user can understand and fix
(wrong file type, empty file, unreadable format, ...).

`code` is a short machine-readable label the frontend can react to;
`message` is the human-readable explanation shown on screen."""


class LogAnalysisError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
