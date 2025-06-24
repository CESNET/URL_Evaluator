import yaml
import os

class Config:
    def __init__(self, path) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"File {path} not found")
        with open(path) as file:
            try:
                self.config = yaml.safe_load(file)
            except yaml.YAMLError as e:
                raise e

    def __getattr__(self, attr_name):
        if attr_name in self.config:
            return self.config[attr_name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{attr_name}'")
