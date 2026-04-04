from setuptools import setup, find_packages

setup(
    name="wifi-killer",
    version="4.0.0",
    description=(
        "Educational Wi-Fi network control and analysis tool – "
        "host discovery, ARP-based MITM, device identification, "
        "and MAC anonymisation."
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="at0m-b0mb",
    license="MIT",
    packages=find_packages(),
    package_data={"wifi_killer": ["data/oui.json"]},
    python_requires=">=3.9",
    install_requires=[
        "scapy>=2.5.0",
        "dnspython>=2.3.0",
    ],
    entry_points={
        "console_scripts": [
            "wifi-killer=wifi_killer.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
