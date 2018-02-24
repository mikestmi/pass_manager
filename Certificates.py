"""
This script contains the functions which manipulate the Certificates the application uses.
First imports the necessary libraries
After that there are the definitions of all the functions which create certificates, create key pairs (public/private),
create certificate signing requests, loads the CA certificate and private key. Finally,exports the user's certificate and
the user's key pair.
"""

from OpenSSL import crypto
import os, random


def create_cert(req, issuerCert, issuerKey, serial, notBefore, notAfter, digest="sha256"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate request to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_version(2)
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


def create_key_pair(type, bits):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    key_pair = crypto.PKey()
    key_pair.generate_key(type, bits)
    return key_pair


def create_cert_request(pkey, digest="sha256", **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key,value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req


def load_CA_cert():
    """
    loads the CA certificate from the application's directory
    :return: The certificate instance
    """
    CA_cert = open("/home/michael/Application/CA/caCert.crt", 'rt').read()
    certif = crypto.load_certificate(crypto.FILETYPE_PEM, CA_cert)
    # print(certif)
    return certif


def load_CA_key():
    """
        loads the CA private key from the application's directory
        :return: The private key instance
        """
    CA_key = open("/home/michael/Application/CA/private_key.pem", 'rt').read()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, CA_key)
    # print(key)
    return key


def register_user(name, email):
    """
    Creates a folder with the user's name. Loads the CA certificate and private key. Creates a key pair for the user and
    then constructs a certificate signing request for the user. After that, creates the user's certificate from the csr
    using the CA certificate and private key to sign it. Finally, exports in the folder the user's certificate and the
    key pair (public/private).
    :param name:
    :param email:
    :return: None
    """
    save_path = "/home/michael/Επιφάνεια εργασίας/" + name
    os.mkdir(save_path)

    cert_CA = load_CA_cert()

    key_CA = load_CA_key()

    Pkey = create_key_pair(crypto.TYPE_RSA, 2048)

    csr = create_cert_request(Pkey, CN=name, emailAddress=email)

    serialNum = random.randint(1000, 2000)
    notBef = 0
    notAft = (182 * 24 * 60 * 60)  # days * hours * minutes * seconds

    usr_cert = create_cert(csr, cert_CA, key_CA, serialNum, notBef, notAft)

    Cert = crypto.dump_certificate(crypto.FILETYPE_PEM, usr_cert)
    # print(Cert)
    cert_path = save_path + "/certificate.crt"
    with open(cert_path, 'wb') as f:
        f.write(Cert)

    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, Pkey)
    # print(private_key)
    key_path = save_path + "/private key.pem"
    with open(key_path, 'wb') as f:
        f.write(private_key)

    public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, Pkey)
    # print(public_key)
    key_path = save_path + "/public key.pem"
    with open(key_path, 'wb') as f:
        f.write(public_key)