class MeshcutoverError(Exception):
    """Base error for meshcutover."""


class CaseError(MeshcutoverError):
    """The case document is syntactically or semantically invalid."""

    def __init__(self, message: str, path: str = "$"):
        super().__init__(message)
        self.message = message
        self.path = path

    def to_json(self) -> dict:
        return {
            "status": "input_error",
            "error": {
                "type": "invalid_case",
                "path": self.path,
                "message": self.message,
            },
        }


class PlanDocumentError(MeshcutoverError):
    """The supplied plan document is invalid independently of audit safety."""

    def __init__(self, message: str, path: str = "$.plan"):
        super().__init__(message)
        self.message = message
        self.path = path

    def to_json(self) -> dict:
        return {
            "status": "invalid_plan",
            "error": {
                "type": "invalid_plan_document",
                "path": self.path,
                "message": self.message,
            },
        }
