from setuptools import setup

setup(
    name="audit-securite",
    version="1.0",
    py_modules=["app"],
    install_requires=[
        "typer",
    ],
    entry_points={
        "console_scripts": [
            "audit-securite=app:app", 
        ],
    },
)