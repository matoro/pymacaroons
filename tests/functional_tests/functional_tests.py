from __future__ import unicode_literals
import json

from mock import *
from nose.tools import *

import nacl.bindings

from pymacaroons import Macaroon, Verifier
from pymacaroons.serializers import *
from pymacaroons.exceptions import *
from pymacaroons.utils import *


ZERO_NONCE = truncate_or_pad(
    b'\0', size=nacl.bindings.crypto_secretbox_NONCEBYTES)
ONE_NONCE = truncate_or_pad(
    b'\1', size=nacl.bindings.crypto_secretbox_NONCEBYTES)


class TestMacaroon(object):

    def setup(self):
        pass

    def test_basic_signature(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        assert_equal(
            m.signature,
            'e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f'
        )

    def test_first_party_caveat(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )


    def test_serializing(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            m.serialize(),
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZ\
WQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegR\
K8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )

    def test_serializing_strips_padding(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = acaveat')
        assert_equal(
            m.serialize(),
            # In padded base64, this would end with '=='
            ('MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVz'
             'ZWQgb3VyIHNlY3JldCBrZXkKMDAxN2NpZCB0ZXN0ID0gYWNhdmVhdAowMDJmc2ln'
             'bmF0dXJlIJRJ_V3WNJQnqlVq5eez7spnltwU_AXs8NIRY739sHooCg')
        )

    def test_serializing_max_length_packet(self):
        m = Macaroon(location='test', identifier='blah', key='secret')
        m.add_first_party_caveat('x' * 65526)  # exactly 0xFFFF
        assert_not_equal(
            m.serialize(),
            None
        )

    def test_serializing_too_long_packet(self):
        m = Macaroon(location='test', identifier='blah', key='secret')
        m.add_first_party_caveat('x' * 65527)  # one byte too long
        assert_raises(
            MacaroonSerializationException,
            m.serialize
        )

    def test_deserializing(self):
        m = Macaroon.deserialize(
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaW\
VyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1\
cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_deserializing_accepts_padding(self):
        m = Macaroon.deserialize(
            ('MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVz'
             'ZWQgb3VyIHNlY3JldCBrZXkKMDAxN2NpZCB0ZXN0ID0gYWNhdmVhdAowMDJmc2ln'
             'bmF0dXJlIJRJ_V3WNJQnqlVq5eez7spnltwU_AXs8NIRY739sHooCg==')
        )
        assert_equal(
            m.signature,
            '9449fd5dd6349427aa556ae5e7b3eeca6796dc14fc05ecf0d21163bdfdb07a28'
        )

    def test_serializing_json(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            json.loads(m.serialize(serializer=JsonSerializer()))['signature'],
            "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67"
        )

    def test_deserializing_json(self):
        m = Macaroon.deserialize(
            '{"location": "http://mybank/", "identifier": "we used our secret \
key", "signature": "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c2\
3dbd67", "caveats": [{"cl": null, "cid": "test = caveat", "vid": null}]}',
            serializer=JsonSerializer()
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_serializing_deserializing_json(self):
        m = Macaroon(
            location='http://test/',
            identifier='first',
            key='secret_key_1'
        )
        m.add_first_party_caveat('test = caveat')
        n = Macaroon.deserialize(
            m.serialize(serializer=JsonSerializer()),
            serializer=JsonSerializer()
        )
        assert_equal(m.signature, n.signature)

    def test_verify_first_party_exact_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        v = Verifier()
        v.satisfy_exact('test = caveat')
        verified = v.verify(
            m,
            'this is our super secret key; only we should know it'
        )
        assert_true(verified)

    def test_verify_first_party_general_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('general caveat')

        def general_caveat_validator(predicate):
            return predicate == 'general caveat'

        v = Verifier()
        v.satisfy_general(general_caveat_validator)
        verified = v.verify(
            m,
            'this is our super secret key; only we should know it'
        )
        assert_true(verified)

    def test_third_party_caveat(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat(
            'http://auth.mybank/',
            caveat_key,
            identifier,
            nonce=ZERO_NONCE)
        assert_equal(
            m.signature,
            'd27db2fd1f22760e4c3dae8137e2d8fc1df6c0741c18aed4b97256bf78d1f55c'
        )

    def test_serializing_macaroon_with_first_and_third_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

        n = Macaroon.deserialize(m.serialize())

        assert_equal(
            m.signature,
            n.signature
        )

    def test_prepare_for_request(self):
        # use a fixed nonce to ensure the same signature
        signature = self.generate_macaroon(ZERO_NONCE)
        assert_equal(
            signature,
            '2eb01d0dd2b4475330739140188648cf25dda0425ea9f661f1574ca0a9eac54e'
        )

    @patch('nacl.utils.random')
    def test_defaults_to_random_nonce(self, rand_nonce):
        rand_nonce.return_value = ONE_NONCE
        signature = self.generate_macaroon(None)
        assert_equal(
            signature,
            '97b6b4195737d69388ec20d9bcde5ae631ccab430897a40d9473486110476e70'
        )

    def generate_macaroon(self, nonce):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat(
            'http://auth.mybank/',
            caveat_key,
            identifier,
            nonce=nonce,
        )

        discharge = Macaroon(
            location='http://auth.mybank/',
            key=caveat_key,
            identifier=identifier
        )
        discharge.add_first_party_caveat('time < 2015-01-01T00:00')
        protected = m.prepare_for_request(discharge)
        return protected.signature

    def test_verify_third_party_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

        discharge = Macaroon(
            location='http://auth.mybank/',
            key=caveat_key,
            identifier=identifier
        )
        discharge.add_first_party_caveat('time < 2015-01-01T00:00')
        protected = m.prepare_for_request(discharge)

        v = Verifier()
        v.satisfy_exact('account = 3735928559')
        v.satisfy_exact('time < 2015-01-01T00:00')
        verified = v.verify(
            m,
            'this is a different super-secret key; \
never use the same secret twice',
            discharge_macaroons=[protected]
        )
        assert_true(verified)

    def test_inspect(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(m.inspect(), 'location http://mybank/\nidentifier we used\
 our secret key\ncid test = caveat\nsignature 197bac7a044af33332865b9266e26d49\
3bdd668a660e44d88ce1a998c23dbd67')


