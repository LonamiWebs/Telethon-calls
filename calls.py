import hashlib
import os
import json
import random
from subprocess import Popen

from telethon import TelegramClient
from telethon.tl.functions.messages import GetDhConfigRequest
from telethon.tl.functions.phone import AcceptCallRequest, RequestCallRequest, \
    ConfirmCallRequest
from telethon.tl.types import PhoneCallEmpty, PhoneCallWaiting, \
    PhoneCallRequested, PhoneCallDiscarded, PhoneCall, PhoneCallAccepted, \
    UpdatePhoneCall, PhoneCallProtocol, InputPhoneCall, Updates, UpdateShort
from telethon.utils import get_input_user

try:
    with open('session.conf') as f:
        conf = json.load(f)
        api_id = conf['api_id']
        api_hash = conf['api_hash']
        phone_number = conf['phone_number']
        session_name = conf['session_name']
except Exception as e:
    print('Failed to load session.conf:', repr(e))
    quit()

client = TelegramClient(session_name, api_id, api_hash, process_updates=True)
client.connect()

try:
    top_users = {}
    _, users = client.get_dialogs()
    for u in users:
        try:
            top_users[u.id] = get_input_user(u)
        except ValueError:
            "Not an user"

    # TODO Enhance for security and reliability:
    # https://github.com/danog/MadelineProto/blob/90fc78014eda47b8bf5bfdaaeef435c92884011c/src/danog/MadelineProto/MTProtoTools/AuthKeyHandler.php#L501
    def get_dh_config():
        class DH:
            def __init__(self, dh_config):
                self.p = int.from_bytes(dh_config.p, 'big')
                self.g = dh_config.g
                self.resp = dh_config
        return DH(client(GetDhConfigRequest(0, 256)))

    dh_config = get_dh_config()
    calls = {}

    def get_rand_bytes(length=256):
        return bytes(x ^ y for x, y in zip(
            os.urandom(length), dh_config.resp.random
        ))

    def process_phone_call(call):
        if isinstance(call, PhoneCallEmpty):
            pass
        elif isinstance(call, PhoneCallWaiting):
            print('[CALL] Waiting for', call.participant_id, 'to answer...')
        elif isinstance(call, PhoneCallRequested):
            accept_call(call)
        elif isinstance(call, PhoneCallDiscarded):
            state = calls[call.id]
            print('[CALL]', state.user_id.user_id, 'discarded your call because of', type(call.reason).__name__)
            # del calls[call.id]
        elif isinstance(call, PhoneCall):
            process_full_call(call)
        elif isinstance(call, PhoneCallAccepted):
            print('[CALL] Call accepted by', call.participant_id, '! Doing stage 2')
            call_stage_two(call)
        else:
            print('[call] ignoring', type(call), call)

    def process_update(update):
        if isinstance(update, UpdatePhoneCall):
            print('[CALL] Phone call update:', update.phone_call)
            process_phone_call(update.phone_call)
        elif isinstance(update, Updates):
            for u in update.updates:
                process_update(u)
        elif isinstance(update, UpdateShort):
            process_update(update.update)
        else:
            pass
            #print('Ignoring', type(update).__name__)

    def integer_to_bytes(integer):
        return int.to_bytes(
            integer,
            length=(integer.bit_length() + 8 - 1) // 8,  # 8 bits per byte,
            byteorder='big',
            signed=False
        )

    def get_input_user_by_id(user_id):
        try:
            return top_users[user_id]
        except KeyError:
            raise ValueError('Sorry! I do not know who {} is'.format(user_id))

    class DynamicDict:
        def __setattr__(self, key, value):
            self.__dict__[key] = value

    def accept_call(call):
        PROTOCOL = PhoneCallProtocol(min_layer=65, max_layer=65, udp_p2p=True)
        dhc = get_dh_config()

        state = DynamicDict()
        state.incoming = True
        state.peer = InputPhoneCall(call.id, call.access_hash)
        state.user_id = get_input_user_by_id(call.admin_id)
        state.random_id = random.randint(0, 0x7fffffff - 1)
        # TODO "The client is expected to check whether p is a safe prime"
        # https://core.telegram.org/api/end-to-end/voice-calls
        state.p = dhc.p
        state.g = dhc.g
        state.b = 0
        while not (1 < state.b < state.p - 1):
            # "chooses a random value of b, 1 < b < p-1"
            state.b = int.from_bytes(get_rand_bytes(), 'little')

        state.g_b = pow(dhc.g, state.b, dhc.p)
        state.g_a_hash = call.g_a_hash
        state.my_proto = PROTOCOL

        calls[call.id] = state
        phone_call = client(AcceptCallRequest(
            state.peer, integer_to_bytes(state.g_b), protocol=state.my_proto
        ))

        print('[CALL] Call confirmed:', phone_call)
        return process_phone_call(phone_call.phone_call)

    def calc_fingerprint(key):
        return int.from_bytes(
            bytes(hashlib.sha1(key).digest()[-8:]), 'little', signed=True
        )

    def process_full_call(call):
        state = calls[call.id]
        print('[CALL] Processing full call', call)
        print('[CALL] Full state currently', state.__dict__)
        if state.incoming:
            print('[CALL] Got more info about call from', call.admin_id, 'we have accepted.')
            state.g_a = int.from_bytes(call.g_a_or_b, 'big')

            state.pt_g_a_hash = hashlib.sha256(call.g_a_or_b).digest()
            if state.pt_g_a_hash != state.g_a_hash:
                print('[CALL] HASH(G_A) != G_A_HASH!', state.pt_g_a_hash, state.g_a_hash)
            else:
                print('[CALL] g_a hash is correct!')

            state.key = pow(state.g_a, state.b, state.p)
            state.key_fingerprint = calc_fingerprint(integer_to_bytes(state.key))
            print('[CALL] Calculated fingerprint', repr(state.key_fingerprint), 'with key', repr(state.key))

            state.pt_key_fingerprint = call.key_fingerprint
            if state.pt_key_fingerprint != state.key_fingerprint:
                print('[CALL] Fingerprint mismatch! Got', state.pt_key_fingerprint, 'expected', state.key_fingerprint)

        state.connection = call.connection
        state.alternative_connections = call.alternative_connections

        calls[call.id] = state

        print('[CALL] Call #', call.id, 'ready!')
        #print('Please copy this to clipboard:')
        #print('"""')
        #print(dump_call_for_cli(state))
        #print('"""')
        print('[CALL] Calling makefile...')
        old = os.path.abspath(os.curdir)
        os.chdir('/home/lonami/Desktop/voip/libtgvoip/build')

        with open('keys.h', 'w') as f:
            f.write(dump_call_for_cli(state))
        with open('CallMakefile', 'w') as f:
            f.write('''all: build run

build:
  #clang -std=c++1z main.cpp -I{..,../webrtc_dsp,../libraries/include,../libraries/include/opus} ../build/libtgvoip.a -L../libraries/lib -lcrypto -lopenal -lopus -lc++ -framework CoreAudio -lc++ -framework AudioToolbox -framework Foundation
  g++ -std=c++1z main.cpp -I{..,../webrtc_dsp,../libraries/include,../libraries/include/opus} ../build/libtgvoip.a -L../libraries/lib -pthread -ldl -lcrypto -lopenal -lopus

run:
  ./a.out''')
        Popen(['make', '-f', 'CallMakefile'])

        os.chdir(old)

    def call_me_maybe(input_user):
        PROTOCOL = PhoneCallProtocol(min_layer=65, max_layer=65, udp_p2p=True)

        dhc = get_dh_config()
        state = DynamicDict()
        state.incoming = False

        state.user_id = input_user
        state.random_id = random.randint(0, 0x7fffffff - 1)

        state.g = dhc.g
        state.p = dhc.p

        state.a = 0
        while not (1 < state.a < state.p - 1):
            # "A chooses a random value of a, 1 < a < p-1"
            state.a = int.from_bytes(get_rand_bytes(), 'little')

        state.g_a = pow(state.g, state.a, state.p)
        state.g_a_hash = hashlib.sha256(integer_to_bytes(state.g_a)).digest()
        state.my_proto = PROTOCOL

        phone_call = client(RequestCallRequest(
            user_id=state.user_id,
            random_id=state.random_id,
            g_a_hash=state.g_a_hash,
            protocol=state.my_proto
        ))

        phone_call = phone_call.phone_call
        state.peer = InputPhoneCall(phone_call.id, phone_call.access_hash)
        calls[phone_call.id] = state
        return process_phone_call(phone_call)

    def call_stage_two(call):
        state = calls[call.id]
        state.prt_proto = call.protocol  # TODO Hm, why not my_proto?
        print('prt', state.prt_proto)
        print('myp', state.my_proto)

        state.g_b = int.from_bytes(call.g_b, 'little')
        state.key = pow(state.g_b, state.a, state.p)
        state.key_fingerprint = calc_fingerprint(integer_to_bytes(state.key))

        calls[call.id] = state

        phone_call = client(ConfirmCallRequest(
            peer=InputPhoneCall(call.id, call.access_hash),
            g_a=state.g_a,
            key_fingerprint=state.key_fingerprint,
            protocol=state.my_proto
        ))

        print('[CALL] Call confirmed:', phone_call)
        return process_phone_call(phone_call.phone_call)

    def dump_call_for_cli(state):
        def dump_bytes(b):
            return '"\\x{}"'.format('\\x'.join(hex(x)[2:].zfill(2) for x in b))

        def dump_endpoint(conn):
            return '\n'.join([
                '{',
                'auto ipv4 = IPv4Address("{}");'.format(conn.ip),
                'auto ipv6 = IPv6Address("{}");'.format(conn.ipv6),
                'endpoints.emplace_back({}, {}, ipv4, ipv6, (char) EP_TYPE_UDP_RELAY, (unsigned char*) {});'.format(
                    conn.id, conn.port, dump_bytes(conn.peer_tag)
                ),
                '};'
            ])

        ret = ['\n\n\n\n']
        ret.append('is_outgoing = {};'.format('false' if state.incoming else 'true'))
        ret.append('key = {};'.format(dump_bytes(integer_to_bytes(state.key))))

        ret.append(dump_endpoint(state.connection))
        for conn in state.alternative_connections:
            ret.append(dump_endpoint(conn))

        ret.append('\n\n\n\n')
        return '\n'.join(ret)

    while True:
        process_update(client.updates.poll())

finally:
    client.disconnect()
