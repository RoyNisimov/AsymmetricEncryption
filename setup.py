from setuptools import setup, find_packages

DESC = 'A simple asymmetric encryption module'
LONG_DESC = "Showcases protocols and has a lot of cryptographic functions"
setup(
    name="asymmetric-encryption",
    version="0.2.1",
    author="Roy Nisimov, jacebalaron (Daniel Gaisenberg)",
    description=DESC,
    long_description_content_type="text/markdown",
    long_description=LONG_DESC,
    packages=find_packages(),
    url='https://github.com/RoyNisimov/AsymmetricEncryption',
    license='MIT',
    install_requires=[],
    keywords=['python', 'cipher', 'asymmetric encryptions', 'signing', 'verifying', 'protocols', 'encryption', 'decryption', "signature", "ring signature", "rsa", "dsa", "ecc"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
