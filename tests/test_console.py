import pytest
from unittest.mock import MagicMock
import datetime
from dateutil.tz import tzutc
from aws_saml_login.saml import authenticate, assume_role, write_aws_credentials, get_boto3_session
from aws_saml_login.saml import AssumeRoleFailed


def test_assume_role(monkeypatch):
    sts = MagicMock()
    sts.assume_role_with_saml.return_value = {
        'Audience': 'https://signin.aws.amazon.com/saml',
        'Credentials': {
            'AccessKeyId': 'abcdef',
            'Expiration': datetime.datetime(2015, 12, 1, 14, 37, 38, tzinfo=tzutc()),
            'SecretAccessKey': 'GEHEIM',
            'SessionToken': 'toktok'
        },
        'Issuer': 'https://idp.example.org/shibboleth'
    }
    monkeypatch.setattr('boto3.client', MagicMock(return_value=sts))

    assert ('abcdef', 'GEHEIM', 'toktok') == assume_role('saml_xml', 'provider_arn', 'role_arn')


def test_assume_role_except(monkeypatch):
    sts = MagicMock()
    sts.assume_role_with_saml.side_effect = Exception('anything is wrong')
    monkeypatch.setattr('boto3.client', MagicMock(return_value=sts))

    with pytest.raises(AssumeRoleFailed):
        assume_role('saml_xml', 'provider_arn', 'role_arn')
