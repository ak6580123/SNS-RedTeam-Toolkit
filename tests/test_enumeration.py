from scripter.recon.enumeration import parse_service


def test_parse_openssh_banner():
    service, version = parse_service(22, "SSH-2.0-OpenSSH_7.4")
    assert service == "ssh"
    assert version == "7.4"


def test_parse_vsftpd_banner():
    service, version = parse_service(21, "220 (vsFTPd 2.3.4)")
    assert service == "ftp"
    assert version == "2.3.4"


def test_parse_apache_server_header():
    banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n"
    service, version = parse_service(80, banner)
    assert service == "http"
    assert version == "2.4.29"


def test_parse_unknown_banner_falls_back_to_port_hint():
    service, version = parse_service(6379, "")
    assert service == "redis"
    assert version is None


def test_parse_irc_falls_back_to_port_hint():
    service, version = parse_service(6667, "")
    assert service == "irc"
    assert version is None


def test_parse_completely_unknown_port_and_banner():
    service, version = parse_service(31337, "garbage")
    assert service is None
    assert version is None
