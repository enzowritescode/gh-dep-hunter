from abc import ABC, abstractmethod
from typing import List, Set, Tuple, Dict, Optional
import requests


class BaseDetector(ABC):
    @abstractmethod
    def search_files(self, session: requests.Session, org: str, repo_full_name: str) -> Tuple[List[dict], bool]:
        pass

    @abstractmethod
    def process_repositories(self, session: requests.Session, org: str, repo_type: str, targets: List[Tuple[str, str]], include_archived: bool = False) -> Tuple[Set[str], List[dict], int, List[str]]:
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
