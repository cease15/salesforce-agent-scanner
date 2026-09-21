#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="sf-agent-scanner",
    version="1.0.0",
    author="cease15",
    author_email="cease15@gmail.com",
    description="Universal compiler-grade scanner and quality gate for Salesforce Apex, LWC, and Metadata Security across all CI/CD pipelines.",
    long_description=open("README.md").read() if open("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sf-agent-scan=sf_agent_scanner.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
