use std::{
    env, fs,
    io::{stdout, BufReader, Read, Write},
    net::TcpStream,
};

use anyhow::{Ok, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use hello_aarch64_wifi_adb::{adb::*, transport::*, types::*};

use openssl::{
    self,
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslContextBuilder, SslMethod, SslStream, SslVersion},
    x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
};

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<String>>();
    let port = args.get(1).unwrap().parse::<u16>()?;
    let stream = TcpStream::connect(format!("localhost:{}", port))?;
    let mut transport = ATransport::new(stream);

    send_acnxn(&mut transport)?;
    let packet = transport.read_apacket()?;
    assert_eq!(A_STLS, packet.msg.command);

    let mut transport = handle_slts(transport)?;
    let packet = transport.read_apacket()?;
    assert_eq!(A_CNXN, packet.msg.command);

    echo_hello(&mut transport)?;
    let packet = transport.read_apacket()?;
    assert_eq!(A_OKAY, packet.msg.command);

    let packet = transport.read_apacket()?;
    assert_eq!(A_WRTE, packet.msg.command);
    print_hello(&packet)?;

    Ok(())
}

pub fn send_acnxn<S>(transport: &mut ATransport<S>) -> Result<usize>
where
    S: Read + Write,
{
    let payload = vec![];
    let mut packet = APacket::new(A_CNXN);
    packet.msg.arg0 = A_VERSION;
    packet.msg.arg1 = MAX_PAYLOAD;
    packet.msg.data_length = payload.len() as u32;
    packet.payload = payload;

    transport.send_apacket(packet)
}

fn echo_hello<S>(transport: &mut ATransport<S>) -> Result<usize>
where
    S: Read + Write,
{
    let payload = Vec::from("shell,v2,raw:echo Hello, World!");
    let mut packet = APacket::new(A_OPEN);
    packet.msg.arg0 = 1;
    packet.msg.data_length = payload.len() as u32;
    packet.payload = payload;
    transport.send_apacket(packet)
}

fn print_hello(packet: &APacket) -> Result<()> {
    let mut buffer = BufReader::new(packet.payload.as_slice());
    let mut v = vec![0; 1];
    buffer.read_exact(&mut v)?;
    assert_eq!(1, v[0]);
    let len = buffer.read_u32::<LittleEndian>()?;
    let mut buf = vec![0; len as usize];
    buffer.read_exact(&mut buf)?;
    print!("{}", String::from_utf8(buf)?);
    stdout().flush()?;
    Ok(())
}

fn handle_slts(mut transport: ATransport<TcpStream>) -> Result<ATransport<SslStream<TcpStream>>> {
    // send_tls_request
    let mut packet = APacket::new(A_STLS);
    packet.msg.arg0 = A_STLS_VERSION;
    packet.msg.data_length = 0;
    transport.send_apacket(packet)?;

    // adb_auth_tls_handshake
    unsafe { adb_auth_tls_handshake(transport) }
}

unsafe fn adb_auth_tls_handshake(
    transport: ATransport<TcpStream>,
) -> Result<ATransport<SslStream<TcpStream>>> {
    let mut ssl_ctx = SslContextBuilder::new(SslMethod::tls())?;
    ssl_ctx.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ssl_ctx.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    let mut pem_path = env::var_os("HOME").unwrap();
    pem_path.push("/.android/adbkey");
    let mut reader = BufReader::new(fs::File::open(pem_path)?);
    let mut pem_buf = vec![];
    reader.read_to_end(&mut pem_buf)?;
    let rsa = Rsa::private_key_from_pem(&pem_buf)?;

    let x509 = generate_x509_certificate(rsa.clone())?;
    ssl_ctx.set_certificate(&x509)?;
    ssl_ctx.set_private_key(&PKey::from_rsa(rsa).unwrap())?;

    let mut ssl = openssl::ssl::Ssl::new(&ssl_ctx.build())?;
    ssl.set_connect_state();
    let stream = transport.stream();
    let mut stream = SslStream::new(ssl, stream)?;
    stream.do_handshake()?;
    let mut buf = vec![1];
    stream.ssl_peek(&mut buf)?;
    Ok(ATransport::new(stream))
}

fn generate_x509_certificate(rsa: Rsa<Private>) -> Result<openssl::x509::X509> {
    let mut builder = openssl::x509::X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_serial_number(&BigNum::from_u32(2)?.to_asn1_integer().unwrap())?;
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap())?;
    builder.set_not_after(&Asn1Time::days_from_now(365 * 10).unwrap())?;
    let pkey = PKey::from_rsa(rsa)?;
    builder.set_pubkey(&pkey)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_identifier)?;

    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();
    Ok(cert)
}
