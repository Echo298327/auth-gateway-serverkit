from setuptools import setup, find_packages

setup(
    name="auth-gateway-serverkit",
    version="0.0.50",
    author="Echo298327",
    author_email="shalomber17@gmail.com",
    description="auth gateway server kit",
    packages=find_packages(),
    install_requires=[],
    entry_points={"console_scripts": ["auth-gateway-serverkit = src.main:main"]},
)
