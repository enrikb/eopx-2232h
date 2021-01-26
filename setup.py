import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="eopx-2232H",
    version="0.0.1",
    author="Enrik Berkhan",
    author_email="enrikb@github.com",
    description="Quirks needed to run eopx with and FTDI 2232H chip.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/enrikb/eopx-2232h",
    packages=["eopx_2232h"],
    package_data={"eopx_2232h": ["*.js"]},
    include_package_data = True,
    scripts=["eopx.py", "DolphinView.py", "DolphinStudio.py"],
    install_requires=["frida ~= 14.2.8", "frida-tools ~= 9.1.0"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: JavaScript",
        "Development Status :: 4 - Beta",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Operating System :: Microsoft :: Windows",
        "Intended Audience :: Developers",
    ],
    python_requires='>=3.6',
)