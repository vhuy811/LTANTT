from setuptools import find_packages, setup

setup(
    name="securecrypto",
    version="0.1.0",
    description="Thư viện mật mã: AES-256-GCM, RSA-PSS, Argon2",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41",
        "argon2-cffi>=21.3",
        "flask>=2.2",
    ],
    entry_points={
        "console_scripts": [
            "securecrypto-cli=securecrypto.cli:main",
        ],
    },
)
