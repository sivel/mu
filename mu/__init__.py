#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2015 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import (absolute_import, division, print_function)

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import uuid
import zipfile

from contextlib import contextmanager

from distutils import log

import boto3

from botocore.exceptions import ClientError

from py.error import ENOENT
from py.path import local

import setuptools
from setuptools import find_packages
from setuptools.command.build_py import build_py
from setuptools.command.egg_info import FileList
import setuptools.command.sdist
from setuptools.dist import Distribution

from tox.config import DepConfig, TestenvConfig
import tox.session


__version__ = '1.0.1'
__metaclass__ = type


class Mu:
    def __init__(self, config_file='lambda.json', zip_file=None,
                 with_pyc=False):
        self.config_file = config_file
        self.config_data = {}

        self.with_pyc = with_pyc

        self.venv = None

        self.build = None
        self.sdist = None

        self.files = []

        log.set_threshold(log.ERROR)

        self.read_config()

        if zip_file:
            self.zip_file = zip_file
        else:
            self.zip_file = '%s.zip' % self.config_data.get('name', 'lambda')
        self.zip = None

        self.prepare_tox()
        self.prepare_setuptools()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.venv.path.remove()
        except (ENOENT, AttributeError):
            pass

    @contextmanager
    def _zipper(self):
        z = zipfile.ZipFile(self.zip_file, 'w', zipfile.ZIP_DEFLATED)
        yield z
        z.close()

    def read_config(self):
        try:
            with open(self.config_file, 'rbU') as f:
                self.config_data = json.load(f)
        except (OSError, IOError) as e:
            raise SystemExit('Could not load "%s" (%s)' % (self.config_file,
                                                           e))
            self.config_data = {}

        return self.config_data

    def prepare_tox(self):
        toxini = os.path.join(os.path.dirname(__file__), 'tox.ini')
        config = tox.session.prepare(['-c', toxini])
        name = uuid.uuid4().hex
        envconfig = TestenvConfig(name, config, None, None)
        envconfig.envdir = local('%s/%s' % (config.toxworkdir, name))
        envconfig.envlogdir = local('%s/log-%s' % (config.toxworkdir, name))
        envconfig.basepython = sys.executable
        envconfig.sitepackages = False
        envconfig.downloadcache = False
        envconfig.pip_pre = False
        envconfig.setenv = []
        envconfig.install_command = 'pip install {opts} {packages}'.split()
        config.envconfigs[name] = envconfig

        session = tox.session.Session(config)
        self.venv = session.getvenv(name)

    def prepare_setuptools(self):
        dist = Distribution()
        dist.script_name = 'mu.py'

        self.sdist = setuptools.command.sdist.sdist(dist)
        self.sdist.filelist = FileList()

        self.build = build_py(dist)
        self.build.packages = []
        packages = self.config_data.get('packages')
        if packages is not None:
            self.build.packages.extend(find_packages(**packages))
        self.build.py_modules = self.config_data.get('py_modules', [])

    def get_file_list(self):
        for module in self.build.find_all_modules():
            self.files.append((os.path.abspath(module[2]), module[2]))

        deps = self.config_data.get('deps', [])
        if deps:
            ixserver = self.venv.envconfig.config.indexserver['default']
            self.venv.create()
            self.venv.envconfig.deps = [DepConfig(dep, ixserver)
                                        for dep in deps]
            site_packages = self.venv.envconfig.envsitepackagesdir()
            self.venv.install_deps()

            for root, _, files in os.walk(site_packages):
                for filename in files:
                    if not self.with_pyc and re.search('\.py[co]$', filename):
                        continue
                    filepath = os.path.abspath(os.path.join(root, filename))
                    arcname = filepath[len(site_packages) + 1:]
                    self.files.append((filepath, arcname))

        self.sdist.finalize_options()
        self.sdist.get_file_list()

        for _file in self.sdist.filelist.files:
            self.files.append((os.path.abspath(_file), _file))

        return self.files

    def create_zip(self):
        with self._zipper() as z:
            for _file in self.files:
                z.write(*_file)

    def _ensure_iam_default_role(self, session):
        iam = session.client('iam')
        try:
            role_resp = iam.get_role(RoleName='lambda_basic_execution')
        except ClientError:
            name = 'lambda_basic_execution'
            role_resp = iam.create_role(
                Path='/',
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps({
                    'Statement': [
                        {
                            'Action': 'sts:AssumeRole',
                            'Effect': 'Allow',
                            'Principal': {
                                'Service': 'lambda.amazonaws.com'
                            },
                            'Sid': ''
                        }
                    ],
                    'Version': '2012-10-17'
                }, indent=2)
            )

            iam.put_role_policy(
                RoleName=name,
                PolicyName=name,
                PolicyDocument=json.dumps({
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents"
                            ],
                            "Resource": "arn:aws:logs:*:*:*"
                        }
                    ]
                }, indent=2)
            )

        return role_resp['Role']['Arn']

    def _get_sha256(self):
        sha = hashlib.sha256()
        with open(self.zip_file, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                sha.update(chunk)
        return base64.b64encode(sha.digest())

    def upload(self, profile='default'):
        session = boto3.Session(
            region_name=self.config_data.get('region', 'us-east-1'),
            profile_name=profile
        )

        client = session.client('lambda')

        if self.config_data.get('role'):
            role = self.config_data.get('role')
        else:
            role = self._ensure_iam_default_role(session)
            # iam = session.client('iam')
            # try:
            #     role_resp = iam.get_role(RoleName='lambda_basic_execution')
            # except ClientError:
            #     name = 'lambda_basic_execution'
            #     role_resp = iam.create_role(
            #         Path='/',
            #         RoleName=name,
            #         AssumeRolePolicyDocument=json.dumps({
            #             'Statement': [
            #                 {
            #                     'Action': 'sts:AssumeRole',
            #                     'Effect': 'Allow',
            #                     'Principal': {
            #                         'Service': 'lambda.amazonaws.com'
            #                     },
            #                     'Sid': ''
            #                 }
            #             ],
            #             'Version': '2012-10-17'
            #         }, indent=2)
            #     )

            #     iam.put_role_policy(
            #         RoleName=name,
            #         PolicyName=name,
            #         PolicyDocument=json.dumps({
            #             'Version': '2012-10-17',
            #             'Statement': [
            #                 {
            #                     "Effect": "Allow",
            #                     "Action": [
            #                         "logs:CreateLogGroup",
            #                         "logs:CreateLogStream",
            #                         "logs:PutLogEvents"
            #                     ],
            #                     "Resource": "arn:aws:logs:*:*:*"
            #                 }
            #             ]
            #         }, indent=2)
            #     )

            # role = role_resp['Role']['Arn']

        try:
            func = client.get_function(FunctionName=self.config_data['name'])
        except ClientError:
            func = None
            for _ in range(5):
                try:
                    with open(self.zip_file, 'rb') as f:
                        func = client.create_function(
                            FunctionName=self.config_data['name'],
                            Runtime='python2.7',
                            Role=role,
                            Handler=self.config_data['handler'],
                            Code={'ZipFile': f.read()},
                            Description=self.config_data.get('description',
                                                             ''),
                            Timeout=self.config_data.get('timeout', 3),
                            MemorySize=self.config_data.get('memory', 128),
                            Publish=self.config_data.get('publish', True),
                        )
                except ClientError as e:
                    role_msg = ('The role defined for the task cannot be '
                                'assumed by Lambda.')
                    if e.response['Error']['Message'] == role_msg:
                        time.sleep(2)
                    else:
                        raise
                else:
                    break
            if not func:
                raise SystemExit('Error creating Lambda function: %s' %
                                 e.response['Error']['Message'])
        else:
            if self._get_sha256() != func['Configuration']['CodeSha256']:
                with open(self.zip_file, 'rb') as f:
                    client.update_function_code(
                        FunctionName=self.config_data['name'],
                        ZipFile=f.read(),
                        Publish=self.config_data.get('publish', True)
                    )

            client.update_function_configuration(
                FunctionName=self.config_data['name'],
                Role=role,
                Handler=self.config_data['handler'],
                Description=self.config_data.get('description', ''),
                Timeout=self.config_data.get('timeout', 3),
                MemorySize=self.config_data.get('memory', 128)
            )


def main():
    parser = argparse.ArgumentParser(prog='mu')
    parser.add_argument('config', nargs='?', default='lambda.json',
                        help='JSON file describing this lambda function. '
                             'Default %(default)s')
    parser.add_argument('--with-pyc', action='store_true',
                        help='Package pyc/pyo files')
    parser.add_argument('--zip-file', default='lambda.zip',
                        help='Name to give ZIP file. Default %(default)s')
    parser.add_argument('--profile', default='default',
                        help='boto/awscli profile name. Default %(default)s')
    parser.add_argument('--zip-only', action='store_true',
                        help='Only create the ZIP file, do not upload')
    args = parser.parse_args()
    with Mu(config_file=args.config, with_pyc=args.with_pyc) as mu:
        mu.get_file_list()
        mu.create_zip()
        if not args.zip_only:
            mu.upload(args.profile)

if __name__ == '__main__':
    main()
