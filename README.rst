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

This Python package provides some helper functions to allow programmatic retrieval of temporary AWS credentials from STS_ (Security Token Service) when using federated login with `Shibboleth Identity Provider`_. Currently it supports only Shibboleth IDP.

The implementation relies on HTML parsing of the Shibboleth redirect page (HTML form) and the AWS role selection page.

This package requires Python 3.4.

Installation
============

.. code-block:: bash

    $ sudo pip3 install --upgrade aws-saml-login

Usage
=====

.. code-block:: python

    from aws_saml_login import authenticate, assume_role, write_aws_credentials, get_boto3_session

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

    # get boto3 session
    session = get_boto3_session(key_id, secret, session_token)
    ec2 = session.resource('ec2', 'eu-west-1')
    iam = session.client('iam')

    # get boto3 session with default region eu-central-1
    session = get_boto3_session(key_id, secret, session_token, 'eu-central-1')
    ec2 = session.resource('ec2')

    # get session for the first 5 roles
    sessions = {}
    for role in roles[:5]:
      provider_arn, role_arn, account_name = role
      key_id, secret, session_token, expiration = assume_role(saml_xml, provider_arn, role_arn)
      sessions['{} {}'.format(account_name,role_arn.split(':')[-1])] = get_boto3_session(key_id, secret, session_token)

    for key in sessions.keys():
      print('Key: {} / AccountAlias: {}'
            .format(key,
                    sessions[key].client('iam').list_account_aliases()['AccountAliases']))
    # AWS SDK (e.g. boto) can be used to call AWS endpoints

.. _STS: http://docs.aws.amazon.com/STS/latest/UsingSTS/Welcome.html
.. _Shibboleth IDP: http://shibboleth.net/products/identity-provider.html


shibboleth configuration
========================

.. code-block:: xml

    <rp:RelyingPartyGroup ...>
        ...
        <!-- ========================================== -->
        <!--      Metadata Configuration                -->
        <!-- ========================================== -->
        <!-- MetadataProvider the combining other MetadataProviders -->
        <metadata:MetadataProvider id="ShibbolethMetadata" xsi:type="metadata:ChainingMetadataProvider">
            ...
            <metadata:MetadataProvider id="amazon-webservices" xsi:type="metadata:FileBackedHTTPMetadataProvider"
                metadataURL="https://signin.aws.amazon.com/static/saml-metadata.xml"
                backingFile="shibboleth-idp/metadata/amazon-webservices.xml">
            </metadata:MetadataProvider>
            ...
        </metadata:MetadataProvider>
        ...
        <rp:RelyingParty id="urn:amazon:webservices"
            provider="https://myidp.example.org/shibboleth"
            defaultSigningCredentialRef="IdPCredential">
              <rp:ProfileConfiguration xsi:type="saml:SAML2SSOProfile" includeAttributeStatement="true"
                  assertionLifetime="PT5M" assertionProxyCount="0"
                  signResponses="never" signAssertions="always"
                  encryptAssertions="never" encryptNameIds="never"/>
        </rp:RelyingParty>
        ...
    </rp:RelyingPartyGroup>

    <resolver:AttributeResolver ...>
        ...
        <!-- ========================================== -->
        <!--      AWS Connectors                        -->
        <!-- ========================================== -->
        <resolver:AttributeDefinition id="awsRoles" xsi:type="ad:Mapped" sourceAttributeID="memberof">
            <resolver:Dependency ref="corpLDAP"/>
            <resolver:AttributeEncoder
                xsi:type="enc:SAML2String"
                name="https://aws.amazon.com/SAML/Attributes/Role"
                friendlyName="Role" />
            <ad:ValueMap>
                <ad:ReturnValue>arn:aws:iam::$2:saml-provider/Shibboleth,arn:aws:iam::$2:role/Shibboleth-$1</ad:ReturnValue>
                <ad:SourceValue ignoreCase="true">cn=([^,]*),ou=Roles,ou=[^,]*?([0-9]+),ou=AWS.*</ad:SourceValue>
            </ad:ValueMap>
        </resolver:AttributeDefinition>

        <resolver:AttributeDefinition id="awsRoleSessionName" xsi:type="ad:Simple" sourceAttributeID="uid">
            <resolver:Dependency ref="corpLDAP"/>
            <resolver:AttributeEncoder
                xsi:type="enc:SAML2String"
                name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"
                friendlyName="RoleSessionName" />
        </resolver:AttributeDefinition>
        ...
    </resolver:AttributeResolver>

    <afp:AttributeFilterPolicyGroup ...>
        ...
        <afp:AttributeFilterPolicy id="afP_aws">
            <afp:PolicyRequirementRule xsi:type="basic:AttributeRequesterString" value="urn:amazon:webservices" />
            <afp:AttributeRule attributeID="transientId">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
            <afp:AttributeRule attributeID="awsRoles">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
            <afp:AttributeRule attributeID="awsRoleSessionName">
                <afp:PermitValueRule xsi:type="basic:ANY"/>
            </afp:AttributeRule>
        </afp:AttributeFilterPolicy>
        ...
    </afp:AttributeFilterPolicyGroup>

To login, you must open the right providerId with the Unsolicited/SSO URL:
https://myidp.example.org/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices


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
