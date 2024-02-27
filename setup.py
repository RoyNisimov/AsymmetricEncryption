from setuptools import setup, find_packages

DESC = 'A simple asymmetric encryption module'
with open("README.md", 'r') as f:
    LONG_DESC = f.read()
setup(
    name="asymmetric-encryption",
    version="0.0.7",
    author="Roy Nisimov, jacebalaron (Daniel gaisenberg)",
    description=DESC,
    long_description_content_type="text/markdown",
    long_description=LONG_DESC,
    packages=find_packages(),
    url='https://github.com/RoyNisimov/AsymmetricEncryption',
    license='MIT',
    install_requires=[],
    keywords=['python', 'cipher', 'asymmetric encryptions', 'signing', 'verifying', 'protocols', 'encryption', 'decryption'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
