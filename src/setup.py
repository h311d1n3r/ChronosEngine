from setuptools import setup, find_packages
import os
from typing import List

def parse_requirements(req_file_path: str) -> List[str]:
    """!
    @brief Extract dependencies from a requirements.txt file

    @param req_file_path: Path to requirements.txt file
    @return List of dependencies
    """

    with open(req_file_path, 'r') as req_file:
        return [line.strip() for line in req_file if line and not line.startswith('#')]

requirements = parse_requirements(os.path.join(os.path.dirname(__file__), 'requirements.txt'))

setup(
    name="chronos_engine",
    version="0.1",
    packages=find_packages(),
    install_requires=requirements,
    author="HellDiner",
    description="Emulation engine for Chronos dump files"
)