import os
from typing import List
from meramodule.config import Config
class WordlistManager:
    def __init__(self):
        self.config = Config()
        
    def get_directory_wordlist(self) -> List[str]:
        with open(f"{self.config.WORDLIST_DIR}/directories.txt", "r") as f:
            return [line.strip() for line in f.readlines()]
    
    def get_file_wordlist(self) -> List[str]:
        with open(f"{self.config.WORDLIST_DIR}/files.txt", "r") as f:
            return [line.strip() for line in f.readlines()]
    
    def get_parameter_wordlist(self) -> List[str]:
        with open(f"{self.config.WORDLIST_DIR}/parameters.txt", "r") as f:
            return [line.strip() for line in f.readlines()]
