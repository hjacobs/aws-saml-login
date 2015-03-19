import codecs
from textwrap import dedent
from xml.etree import ElementTree
import botocore.session
from bs4 import BeautifulSoup
import click
import keyring
import os
import requests
from aws_saml_login.console import Action, choice


AWS_CREDENTIALS_PATH = '~/.aws/credentials'


def write_aws_credentials(profile, key_id, secret, session_token=None):
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    config = configparser.ConfigParser()
    if os.path.exists(credentials_path):
        config.read(credentials_path)

    config[profile] = {}
    config[profile]['aws_access_key_id'] = key_id
    config[profile]['aws_secret_access_key'] = secret
    if session_token:
        # apparently the different AWS SDKs either use "session_token" or "security_token", so set both
        config[profile]['aws_session_token'] = session_token
        config[profile]['aws_security_token'] = session_token

    with open(credentials_path, 'w') as fd:
        config.write(fd)


def get_saml_response(html: str):
    """
    Parse SAMLResponse from Shibboleth page

    >>> get_saml_response('<input name="a"/>')

    >>> get_saml_response('<body xmlns="bla"><form><input name="SAMLResponse" value="eG1s"/></form></body>')
    'xml'
    """
    soup = BeautifulSoup(html)

    for elem in soup.find_all('input', attrs={'name': 'SAMLResponse'}):
        saml_base64 = elem.get('value')
        xml = codecs.decode(saml_base64.encode('ascii'), 'base64').decode('utf-8')
        return xml


def get_form_action(html: str):
    '''
    >>> get_form_action('<body><form action="test"></form></body>')
    'test'
    '''
    soup = BeautifulSoup(html)
    return soup.find('form').get('action')


def get_role_label(role, account_names: dict=None):
    """
    >>> get_role_label(('arn:aws:iam::123:saml-provider/Shibboleth', 'arn:aws:iam::123:role/Shibboleth-PowerUser'))
    'AWS Account 123 (unknown): Shibboleth-PowerUser'

    >>> get_role_label(('arn:aws:iam::123:saml-provider/A', 'arn:aws:iam::123:role/B'), {'123': 'blub'})
    'AWS Account 123 (blub): B'
    """
    provider_arn, role_arn = role
    number = role_arn.split(':')[4]
    if account_names and number in account_names:
        name = account_names[number]
    else:
        name = 'unknown'
    return 'AWS Account {} ({}): {}'.format(number, name, role_arn.split('/')[-1])


def get_roles(saml_xml: str) -> list:
    """
    Extract SAML roles from SAML assertion XML

    >>> get_roles('''<xml xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Assertion>
    ... <Attribute FriendlyName="Role" Name="https://aws.amazon.com/SAML/Attributes/Role">
    ... <AttributeValue>arn:aws:iam::911:saml-provider/Shibboleth,arn:aws:iam::911:role/Shibboleth-User</AttributeValue>
    ... </Attribute>
    ... </Assertion></xml>''')
    [('arn:aws:iam::911:saml-provider/Shibboleth', 'arn:aws:iam::911:role/Shibboleth-User')]
    """
    tree = ElementTree.fromstring(saml_xml)

    assertion = tree.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')

    roles = []
    for attribute in assertion.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name]'):
        if attribute.attrib['Name'] == 'https://aws.amazon.com/SAML/Attributes/Role':
            for val in attribute.findall('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                provider_arn, role_arn = val.text.split(',')
                roles.append((provider_arn, role_arn))
    return roles


def get_account_names(html: str) -> dict:
    '''
    Parse account names from AWS page

    >>> get_account_names('')
    {}

    >>> get_account_names('<div class="saml-account-name">Account: blub  (123) </div>')
    {'123': 'blub'}

    >>> get_account_names('<div class="saml-account-name">Account: blub  123) </div>')
    {}
    '''
    soup = BeautifulSoup(html)

    accounts = {}
    for elem in soup.find_all('div', attrs={'class': 'saml-account-name'}):
        try:
            name_number = elem.text.split(':', 1)[-1].strip().rstrip(')')
            name, number = name_number.rsplit('(', 1)
            name = name.strip()
            number = number.strip()
            accounts[number] = name
        except:
            # just skip account in case of parsing errors
            pass
    return accounts


def saml_login(profile, region, url, user, password=None, role=None, print_env_vars=False,
               overwrite_default_credentials=False):
    session = requests.Session()
    response = session.get(url)

    keyring_key = 'aws-minion.saml'
    password = password or keyring.get_password(keyring_key, user)
    if not password:
        password = click.prompt('Password', hide_input=True)

    with Action('Authenticating against {url}..', **vars()) as act:
        # NOTE: parameters are hardcoded for Shibboleth IDP
        data = {'j_username': user, 'j_password': password, 'submit': 'Login'}
        response2 = session.post(response.url, data=data)
        saml_xml = get_saml_response(response2.text)
        if not saml_xml:
            act.error('LOGIN FAILED')
            click.secho('SAML login with user "{}" failed, please check your username and password.\n'.format(user) +
                        'You might need to change the password in your keyring (e.g. Mac OS X keychain) ' +
                        'or use the "--password" option.', bold=True, fg='blue')
            return

        url = get_form_action(response2.text)
        encoded_xml = codecs.encode(saml_xml.encode('utf-8'), 'base64')
        response3 = session.post(url, data={'SAMLResponse': encoded_xml})
        account_names = get_account_names(response3.text)

    keyring.set_password(keyring_key, user, password)

    with Action('Checking SAML roles..') as act:
        roles = get_roles(saml_xml)
        if not roles:
            act.error('NO VALID ROLE FOUND')
            return

    if len(roles) == 1:
        provider_arn, role_arn = roles[0]
    elif role:
        matching_roles = [_role for _role in roles if role in get_role_label(_role, account_names)]
        if not matching_roles or len(matching_roles) > 1:
            raise click.UsageError('Given role (--role) was not found or not unique')
        provider_arn, role_arn = matching_roles[0]
    else:
        roles.sort()
        provider_arn, role_arn = choice('Multiple roles found, please select one.',
                                        [(r, get_role_label(r, account_names)) for r in roles])

    with Action('Assuming role "{role_label}"..', role_label=get_role_label((provider_arn, role_arn), account_names)):
        saml_assertion = codecs.encode(saml_xml.encode('utf-8'), 'base64').decode('ascii').replace('\n', '')

        # botocore NEEDS some credentials, but does not care about their actual values
        os.environ['AWS_ACCESS_KEY_ID'] = 'fake123'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'fake123'

        try:
            session = botocore.session.get_session()
            sts = session.get_service('sts')
            operation = sts.get_operation('AssumeRoleWithSAML')

            endpoint = sts.get_endpoint(region)
            endpoint._signature_version = None
            http_response, response_data = operation.call(endpoint, role_arn=role_arn, principal_arn=provider_arn,
                                                          SAMLAssertion=saml_assertion)
        finally:
            del os.environ['AWS_ACCESS_KEY_ID']
            del os.environ['AWS_SECRET_ACCESS_KEY']

        key_id = response_data['Credentials']['AccessKeyId']
        secret = response_data['Credentials']['SecretAccessKey']
        session_token = response_data['Credentials']['SessionToken']

    if print_env_vars:
        # different AWS SDKs expect either AWS_SESSION_TOKEN or AWS_SECURITY_TOKEN, so set both
        click.secho(dedent('''\
        # environment variables with temporary AWS credentials:
        export AWS_ACCESS_KEY_ID="{key_id}"
        export AWS_SECRET_ACCESS_KEY="{secret}"
        export AWS_SESSION_TOKEN="{session_token}")
        export AWS_SECURITY_TOKEN="{session_token}"''').format(**vars()), fg='blue')

    profiles_to_write = set([profile])
    if overwrite_default_credentials:
        profiles_to_write.add('default')

    with Action('Writing temporary AWS credentials..'):
        for prof in profiles_to_write:
            write_aws_credentials(prof, key_id, secret, session_token)
