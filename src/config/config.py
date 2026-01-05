import yaml
import os


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "./config.yaml")
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)
    return config

config = load_config()
os.environ["IDADIR"] = config["idat"]["path"]

if __name__ == "__main__":
    config = load_config()
    print(config)
