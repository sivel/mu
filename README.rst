mu
==

Python module and CLI to package and upload python lambda functions to
AWS Lambda

Installation
------------

::

    pip install python-mu

Configuration
-------------

You will need to have a boto profile created. This can be done using
``awscli``:

::

    pip install awscli
    aws configure

Usage
-----

::

    usage: mu [-h] [--with-pyc] [--zip-file ZIP_FILE] [--profile PROFILE]
              [--zip-only]
              [config]

    positional arguments:
      config               JSON file describing this lambda function. Default
                           lambda.json

    optional arguments:
      -h, --help           show this help message and exit
      --with-pyc           Package pyc/pyo files
      --zip-file ZIP_FILE  Name to give ZIP file. Default lambda.zip
      --profile PROFILE    boto/awscli profile name. Default default
      --zip-only           Only create the ZIP file, do not upload

lambda.json
-----------

::

    {
        "name": "helloworld",
        "description": "Hello, World!",
        "region": "us-east-1",
        "role": "arn:aws:iam::000000000000:role/lambda_basic_execution",
        "handler": "helloworld.lambda_handler",
        "memory_size": 128,
        "timeout": 3,
        "py_modules": [
            "helloworld"
        ],
        "packages": {
            "exclude": [
                "tests",
                "tests.*"
            ]
        },
        "deps": [
            "requests",
            "-rrequirements.txt"
        ],
        "publish": true
    }

