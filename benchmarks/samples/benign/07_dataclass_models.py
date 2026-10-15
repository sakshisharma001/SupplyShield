"""Data models with dataclasses."""
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class UserProfile:
    user_id: int
    username: str
    roles: List[str] = field(default_factory=list)
    is_active: bool = True

    def has_role(self, role: str) -> bool:
        return role in self.roles
