from setuptools import setup, find_packages

setup(
    name="knowyourenemy",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "requests",
        "rich",
        "python-dotenv",
        "python-whois",
        # add other dependencies here
    ],
    entry_points={
        "console_scripts": [
            "kye=main:enrich",  # kye command runs main.enrich()
        ]
    },
    author="Your Name",
    description="KnowYourEnemy: Threat analysis swiss army knife for SOC Analysts",
    url="https://github.com/yourusername/KnowYourEnemy",
    python_requires=">=3.7",
)
