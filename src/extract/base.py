from abc import ABC, abstractmethod
import requests
import logging
import pandas as pd

class Extractor(ABC):
    def __init__(self, config, headers):
        self.config = config
        self.headers = headers
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def fetch_data(self, endpoint: str, params: dict) -> dict:
        pass

    @abstractmethod
    def process_data(self, data: dict, value_key: str) -> pd.DataFrame:
        pass