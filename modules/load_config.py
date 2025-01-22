import yaml
import os

class Config:
    def __init__(self, path) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"File {path} not found")
        with open(path) as file:
            try:
                config = yaml.safe_load(file)
            except yaml.YAMLError as e:
                raise e
            self.virustotal_key = config["virustotal_key"]
            self.db_path = config["db_path"]
            self.limits = config["limits"]
            self.bl_path = config["bl_path"]
            self.bl_update_time = config["bl_update_time"]
            self.log_file = config["log_file"]
            self.http_proxy = config["http_proxy"]


