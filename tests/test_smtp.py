import os

from httpreplay.reader import PcapReader
from httpreplay.smegma import TCPPacketStreamer, TLSStream
from httpreplay.cut import smtp_handler
from httpreplay.cobweb import SmtpProtocol


class SmtpTest(object):
    handlers = {
        587: smtp_handler,
        25: smtp_handler
    }

    def __init__(self, pcapfile):
        self.f = open(pcapfile, "rb")
        self.reader = PcapReader(self.f)
        self.reader.raise_exceptions = False
        self.reader.tcp = TCPPacketStreamer(self.reader, self.handlers)


    def get_sent_recv(self):

        s = None
        r = None
        for s, ts, prot, sent, recv in self.reader.process():
            s = sent
            r = recv

        self.f.close()
        return s, r


def test_read_smtp_from_to():
    test = SmtpTest(os.path.join("tests", "pcaps", "smtp-auth-login.pcap"))
    sent, recv = test.get_sent_recv()

    expected = [
        ['xxxxxx@xxxxx.co.uk'],
        ['xxxxxx.xxxx@xxxxx.com']
    ]

    output = [
        sent.mail_from,
        sent.mail_to
    ]
    assert expected == output


def test_read_smtp_headers():
    test = SmtpTest(os.path.join("tests", "pcaps", "smtp-auth-login.pcap"))
    sent, recv = test.get_sent_recv()

    expected = [
        'Reply-To: <xxxxxx@xxxxx.co.uk>',
        'From: "WShark User" <xxxxxx@xxxxx.co.uk>',
        'To: <xxxxxx.xxxx@xxxxx.com>',
        'Subject: Test message for capture',
        'Date: Sun, 24 Jun 2007 10:56:03 +0200',
        'MIME-Version: 1.0', 'Content-Type: multipart/mixed;',
        '\tboundary="----=_NextPart_000_0012_01C7B64E.426C8120"',
        'X-Mailer: Microsoft Office Outlook, Build 11.0.5510',
        'Thread-Index: Ace2O6M0WGyVJP3rQCuQePVHKWo5Ag==',
        'X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2900.3138'
    ]

    assert expected == sent.headers


def test_read_smtp_message_body():
    test = SmtpTest(os.path.join("tests", "pcaps", "smtp-auth-login.pcap"))
    sent, recv = test.get_sent_recv()

    expected = "\nThis is a multi-part message in MIME format.\r\n\r\n"

    assert expected == sent.message[0:49]


def test_get_username_password_auth_login():
    test = SmtpTest(os.path.join("tests", "pcaps", "smtp-auth-login.pcap"))
    sent, recv = test.get_sent_recv()

    assert ["galunt", "V1v1tr0n"] == [sent.username, sent.password]


def test_get_username_password_auth_login_arg():

    smtp = SmtpProtocol()
    smtp.init()

    data = "AUTH LOGIN Zm9vZEBiZWVyLnBseg=="
    pass_data = "U2hvb3BEYVdob29wIQ=="
    smtp.parse_request(data)
    smtp.last_rescode = 334
    smtp.last_resmess = "UGFzc3dvcmQ6"
    smtp.parse_request(pass_data)

    expected = ["food@beer.plz", "ShoopDaWhoop!"]

    assert expected == [smtp.request.username, smtp.request.password]


def test_get_username_password_auth_plain():

    smtp = SmtpProtocol()
    smtp.init()

    user_pass = "AHRlc3R1c2VyAEF3M3MwbVA0enpzIQ=="
    smtp.last_rescode = 334
    smtp.request.auth_type = "auth plain"
    smtp.parse_request(user_pass)

    expected = ["testuser", "Aw3s0mP4zzs!"]

    assert expected == [smtp.request.username, smtp.request.password]


def test_get_username_password_auth_plain_arg():

    smtp = SmtpProtocol()
    smtp.init()

    data = "AUTH PLAIN AHRlc3R1c2VyAEF3M3MwbVA0enpzIQ=="
    smtp.parse_request(data)

    expected = ["testuser", "Aw3s0mP4zzs!"]

    assert expected == [smtp.request.username, smtp.request.password]


def test_get_username_cram_md5_challenge():
    smtp = SmtpProtocol()
    smtp.init()

    challenge_res = "ZnJlZCA5ZTk1YWVlMDljNDBhZjJiODRhMGMyYjNiYmFlNzg2ZQ===="
    smtp.last_rescode = 334
    smtp.request.auth_type = "auth cram-md5"
    smtp.parse_request(challenge_res)

    assert "fred" == smtp.request.username


def test_smtp_reply_ok_responses():
    test = SmtpTest(os.path.join("tests", "pcaps", "smtp-auth-login.pcap"))
    sent, recv = test.get_sent_recv()

    expected = [
        '250-smtp006.mail.xxx.xxxxx.com',
        '250-AUTH LOGIN PLAIN XYMCOOKIE',
        '250-PIPELINING', '250 8BITMIME',
        '250 ok',
        '250 ok',
        '250 ok 1182675387 qp 77793'
    ]

    assert expected == recv.ok_responses
