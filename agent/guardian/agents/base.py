from abc import ABC, abstractmethod
from typing import Protocol

from guardian.core.models import GuardianState


class Agent(Protocol):
    name: str

    def run(self, state: GuardianState) -> GuardianState:
        ...


class BaseAgent(ABC):
    name: str

    @abstractmethod
    def run(self, state: GuardianState) -> GuardianState:
        raise NotImplementedError
