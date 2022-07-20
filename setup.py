from setuptools import setup

setup(
    name="acquire",
    packages=[
        "acquire",
        "acquire.outputs",
        "acquire.tools",
        "acquire.uploaders",
    ],
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
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
