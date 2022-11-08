from setuptools import find_packages, setup

setup(
    name="acquire",
    # Acquire gets added seperately to include version.py
    packages=list(map(lambda v: "acquire." + v, find_packages("acquire"))) + ["acquire"],
    install_requires=[
        "dissect.cstruct",
        "dissect.target",
    ],
    extras_require={
        "full": [
            "minio",
            "pycryptodome",
            "requests",
            "rich",
            "dissect.target[full]",
            "requests_toolbelt",
        ]
    },
    entry_points={
        "console_scripts": [
            "acquire=acquire.acquire:main",
            "acquire-decrypt=acquire.tools.decrypter:main",
        ],
    },
    include_package_data=True,
)
