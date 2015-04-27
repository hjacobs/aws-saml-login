import codecs
from xml.etree import ElementTree
import botocore.session
from bs4 import BeautifulSoup
import os
import configparser
import requests


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


def get_account_name(role_arn: str, account_names: dict):
    number = role_arn.split(':')[4]
    if account_names:
        return account_names.get(number)


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


class AuthenticationFailed(Exception):
    def __init__(self):
        pass


class AssumeRoleFailed(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Assuming role failed: {}'.format(self.msg)


def authenticate(url, user, password):
    '''Authenticate against the provided Shibboleth Identity Provider'''

    session = requests.Session()
    response = session.get(url)

    # NOTE: parameters are hardcoded for Shibboleth IDP
    data = {'j_username': user, 'j_password': password, 'submit': 'Login'}
    response2 = session.post(response.url, data=data)
    saml_xml = get_saml_response(response2.text)
    if not saml_xml:
        raise AuthenticationFailed()

    url = get_form_action(response2.text)
    encoded_xml = codecs.encode(saml_xml.encode('utf-8'), 'base64')
    response3 = session.post(url, data={'SAMLResponse': encoded_xml})
    account_names = get_account_names(response3.text)

    roles = get_roles(saml_xml)

    roles = [(p_arn, r_arn, get_account_name(r_arn, account_names)) for p_arn, r_arn in roles]

    return saml_xml, roles


def assume_role(saml_xml, provider_arn, role_arn):
    saml_assertion = codecs.encode(saml_xml.encode('utf-8'), 'base64').decode('ascii').replace('\n', '')

    # botocore NEEDS some credentials, but does not care about their actual values
    os.environ['AWS_ACCESS_KEY_ID'] = 'fake123'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'fake123'

    try:
        session = botocore.session.get_session()
        sts = session.get_service('sts')
        operation = sts.get_operation('AssumeRoleWithSAML')

        endpoint = sts.get_endpoint('eu-west-1')
        endpoint._signature_version = None
        http_response, response_data = operation.call(endpoint, role_arn=role_arn, principal_arn=provider_arn,
                                                      SAMLAssertion=saml_assertion)
    finally:
        del os.environ['AWS_ACCESS_KEY_ID']
        del os.environ['AWS_SECRET_ACCESS_KEY']

    if not response_data or 'Credentials' not in response_data:
        raise AssumeRoleFailed(response_data)

    key_id = response_data['Credentials']['AccessKeyId']
    secret = response_data['Credentials']['SecretAccessKey']
    session_token = response_data['Credentials']['SessionToken']
    return key_id, secret, session_token
