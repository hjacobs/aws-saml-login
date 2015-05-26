==============
AWS SAML Login
==============

.. image:: https://travis-ci.org/zalando/aws-saml-login.svg?branch=master
   :target: https://travis-ci.org/zalando/aws-saml-login
   :alt: Build Status

.. image:: https://coveralls.io/repos/zalando/aws-saml-login/badge.svg
   :target: https://coveralls.io/r/zalando/aws-saml-login
   :alt: Code Coverage

.. image:: https://img.shields.io/pypi/dw/aws-saml-login.svg
   :target: https://pypi.python.org/pypi/aws-saml-login/
   :alt: PyPI Downloads

.. image:: https://img.shields.io/pypi/v/aws-saml-login.svg
   :target: https://pypi.python.org/pypi/aws-saml-login/
   :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/l/aws-saml-login.svg
   :target: https://pypi.python.org/pypi/aws-saml-login/
   :alt: License

This Python package provides some helper functions to allow programmatic retrieval of temporary AWS credentials from STS_ (Security Token Service) when using federated login with `Shibboleth IDP`_.

The implementation relies on HTML parsing of the Shibboleth redirect page (HTML form) and the AWS role selection page.

This package requires Python 3.4.

Installation
============

.. code-block:: bash

    $ sudo pip3 install --upgrade aws-saml-login

Usage
=====

.. code-block:: python

    from aws_saml_login import authenticate, assume_role, write_aws_credentials

    # authenticate against identity provider
    saml_xml, roles = authenticate('https://shibboleth-idp.example.org', user, password)

    print(roles)

    # just use the first role here, we might display a user dialog to choose one
    first_role = roles[0]

    provider_arn, role_arn, account_name = first_role

    # get temporary AWS credentials
    key_id, secret, session_token = assume_role(saml_xml, provider_arn, role_arn)

    # write to ~/.aws/credentials
    write_aws_credentials('default', key_id, secret, session_token)

    # AWS SDK (e.g. boto) can be used to call AWS endpoints

.. _STS: http://docs.aws.amazon.com/STS/latest/UsingSTS/Welcome.html
.. _Shibboleth IDP: http://shibboleth.net/products/identity-provider.html


License
=======

Copyright © 2015 Zalando SE

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
