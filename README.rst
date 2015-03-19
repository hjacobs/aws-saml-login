==============
AWS SAML Login
==============

.. code-block:: bash

    $ pip3 install --upgrade aws-saml-login

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

