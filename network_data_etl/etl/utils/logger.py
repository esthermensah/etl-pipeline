import logging

def get_logger(name="etl"):
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )
    return logging.getLogger(name)
