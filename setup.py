from setuptools import setup, find_packages

setup(
    name="mcp-waf",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "psycopg2-binary==2.9.9",
        "sqlalchemy==2.0.23",
        "requests==2.31.0",
        "beautifulsoup4==4.12.2",
        "docker==6.1.3",
        "aiohttp==3.9.1",
        "pydantic==2.5.2",
        "selenium==4.15.2",
        "lxml==4.9.3",
        "openai==1.6.1",
        "anthropic==0.8.1"
    ],
    python_requires=">=3.8",
)
