DESCRIPTION = "PyMemGrep is a memory grepping tool in Python."

with open("Readme.md", "r") as f:
    LONG_DESCRIPTION = f.read()


CLASSIFIERS = """\
Development Status :: 2 - Pre-Alpha
Intended Audience :: Developers
License :: OSI Approved :: MIT License
Programming Language :: Python
Programming Language :: Python :: 3
Programming Language :: Python :: 3.7
Programming Language :: Python :: 3.8
Programming Language :: Python :: 3.9
Programming Language :: Python :: 3 :: Only
Programming Language :: Python :: Implementation :: CPython
Topic :: Software Development
Typing :: Typed
Operating System :: Microsoft :: Windows
"""

INSTALL_REQUIREMENTS = """\
psutil>=5.7
"""


def setup_pkg():
    import setuptools

    metadata = dict(
        name="pymemgrep",
        version="0.0.1",
        author="Rebuild",
        author_email="admin@rebuild.moe",
        license="MIT",
        description=DESCRIPTION,
        long_description=LONG_DESCRIPTION,
        long_description_content_type="text/markdown",
        classifiers=[_f for _f in CLASSIFIERS.split("\n") if _f],
        platforms=["Windows"],
        python_requires=">=3.7",
        install_requires=[_f for _f in INSTALL_REQUIREMENTS.split("\n") if _f],
        packages=setuptools.find_packages("src"),
    )

    setuptools.setup(**metadata)


if __name__ == "__main__":
    setup_pkg()
