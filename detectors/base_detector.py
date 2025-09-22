from abc import ABC, abstractmethod
from typing import List, Tuple, Dict, Optional
import requests


class BaseDetector(ABC):
    @abstractmethod
    def search_files(self, session: requests.Session, org: str, repo_full_name: str) -> List[dict]:
        pass

    @abstractmethod
    def fetch_content(self, session: requests.Session, item: dict) -> Optional[str]:
        pass

    @abstractmethod
    def parse_dependencies(self, content: str) -> List[Tuple[str, str]]:
        pass

    @abstractmethod
    def find_matches(self, dependencies: List[Tuple[str, str]], targets: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        pass
