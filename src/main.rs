use zmq::{Context, SocketType};
use env_logger::Env;
use std::thread;
use reqwest::Error;
use serde_json::Value;
use std::time::Duration;
use std::env;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

const ZAP_DOMAIN: &str = "inproc://zeromq.zap.01";

fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();

    let frontend_address = format!("tcp://*:{}", env::var("FRONTEND_PORT").unwrap());
    let backend_address = format!("tcp://*:{}", env::var("BACKEND_PORT").unwrap());

    let secret_key = env::var("SECRET_KEY").unwrap();
    let public_key = env::var("PUBLIC_KEY").unwrap();

    let backend_authentication = env::var("BACKEND_AUTHENTICATION").unwrap_or("false".to_string());


    let mut reqwest_client = reqwest::Client::builder().build().unwrap();


    let ctx = Context::new();
    
    let zap_handler = ctx.socket(SocketType::ROUTER).unwrap();
    zap_handler.set_linger(0).unwrap();
    zap_handler.bind(ZAP_DOMAIN).unwrap();
    thread::spawn(move || authenticator(zap_handler, &mut reqwest_client));
    
    let frontend = ctx.socket(SocketType::XPUB).unwrap();
    frontend.set_affinity(0).unwrap();
    frontend.set_rcvhwm(2).unwrap();
    frontend.set_sndhwm(2).unwrap();
    frontend.set_zap_domain("example").unwrap();
    frontend.set_curve_publickey(public_key.as_bytes()).unwrap();
    frontend.set_curve_secretkey(secret_key.as_bytes()).unwrap();
    frontend.set_curve_server(true).unwrap();
    frontend.bind(&frontend_address).unwrap();

    
    let backend = ctx.socket(SocketType::XSUB).unwrap();
    backend.set_affinity(1).unwrap();
    if backend_authentication.to_lowercase() == "true" {
        backend.set_curve_publickey(public_key.as_bytes()).unwrap();
        backend.set_curve_secretkey(secret_key.as_bytes()).unwrap();
        backend.set_curve_server(true).unwrap();
    }
    
    backend.bind(&backend_address).unwrap();

    //Inicie uma thread separada para enviar mensagens de heartbeat como um cliente
    thread::spawn(move || {
        let backend_heartbeat = format!("tcp://127.0.0.1:{}", env::var("BACKEND_PORT").unwrap());

        let ctx = Context::new();
        let heartbeat_socket = ctx.socket(SocketType::PUB).unwrap();
        if backend_authentication.to_lowercase() == "true" {
        heartbeat_socket
            .set_curve_publickey(public_key.as_bytes())
            .expect("Failed to set public key");
        heartbeat_socket
            .set_curve_secretkey(secret_key.as_bytes())
            .expect("Failed to set secret key");
        heartbeat_socket
            .set_curve_serverkey(public_key.as_bytes())
            .expect("Failed to set server key");
    }
        // Conecte-se ao backend como um cliente normal
        heartbeat_socket.connect(&backend_heartbeat).unwrap();


        loop {
            // Envie uma mensagem de heartbeat com o tópico "heartbeat" e o payload "alive"
            heartbeat_socket.send("heartbeat", zmq::SNDMORE).unwrap();
            heartbeat_socket.send("alive", 0).unwrap();

            // Aguarde 5 segundos antes de enviar a próxima mensagem de heartbeat
            thread::sleep(Duration::from_secs(5));
        }
    });

    // normal proxy

    zmq::proxy(&frontend, &backend).expect("failed proxying");

    

}


fn authenticator(s: zmq::Socket, client: &mut reqwest::Client) -> Result<(), zmq::Error> {
    loop {
        handle_zap_auth(&s, client)?;
        
    }
}

macro_rules! zap_part {
    ($socket:expr) => {{
        let part = $socket.recv_msg(0)?;
        if !part.get_more() {
            error!("Buggy ZAP server did not send a complete message");
            return Ok(());
        }
        part
    }};
}

fn handle_zap_auth(
    s: &zmq::Socket,
    client: &mut reqwest::Client,
) -> Result<(), zmq::Error> {

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut have_envelope = false;
    let mut envelope = vec![];
    while !have_envelope {
        let part = s.recv_msg(0)?;
        if !part.get_more() {
            error!("Buggy ZAP server did not send any message content");
            return Ok(());
        }
        if &*part == b"" {
            have_envelope = true;
        }
        envelope.push(part);
    }
    debug!("starting a ZAP request");

    let version = zap_part!(s);
    let request_id = zap_part!(s);
    let _domain = zap_part!(s);
    let _address = zap_part!(s);
    // info!("Client address: {:?}", _address.as_str().unwrap());
    // info!("Client Domain: {:?}", _domain.as_str().unwrap());
    // info!("Client request id: {:?}", request_id.as_str().unwrap());
    // info!("Client Version: {:?}", version.as_str().unwrap());

    let _identity = zap_part!(s);
    let mechanism = s.recv_msg(0)?;

    let mut have_all_creds = !mechanism.get_more();
    let mut credentials = vec![];
    while !have_all_creds {
        let cred_part = s.recv_msg(0)?;
        have_all_creds = !cred_part.get_more();
        credentials.push(cred_part);
    }

    if &*version != b"1.0" {
        warn!("A ZAP server requested a ZAP version not 1.0");
        return zap_response(
            s,
            envelope,
            request_id,
            500,
            "ZAP handler doesn't recognize that ZAP version",
            "",
        );
    }

    if &*mechanism != b"CURVE" || credentials.len() != 1 {
        error!("This is demo code that only handles simple CURVE auth");
        return zap_response(
            s,
            envelope,
            request_id,
            500,
            "Don't want to handle that mechanism",
            "",
        );
    }

    let peer_key = &credentials[0];
    if (&*peer_key).len() != 32 {
        error!("Buggy ZAP server gave us a key of the wrong length");
        return zap_response(s, envelope, request_id, 500, "wrong key length", "");
    }

    if rt.block_on(is_public_key_allowed(client, &zmq::z85_encode(peer_key).unwrap())).unwrap() {
        info!("Authenticated user {:?}", &zmq::z85_encode(peer_key).unwrap());
        return zap_response(s, envelope, request_id, 200, "OK", &zmq::z85_encode(peer_key).unwrap());
    } else {
        info!("Unauthorized user {:?}", &zmq::z85_encode(peer_key).unwrap());
        return zap_response(s, envelope, request_id, 400, "Unknown Key", "");
    }
}

fn zap_response(
    s: &zmq::Socket,
    envelope: Vec<zmq::Message>,
    request_id: zmq::Message,
    status: i32,
    status_text: &str,
    user_id: &str,
) -> zmq::Result<()> {
    for frame in envelope {
        s.send(frame, zmq::SNDMORE)?;
    }

    s.send("1.0", zmq::SNDMORE)?;
    s.send(request_id, zmq::SNDMORE)?;
    s.send(&format!("{}", status), zmq::SNDMORE)?;
    s.send(status_text, zmq::SNDMORE)?;
    s.send(user_id, zmq::SNDMORE)?;
    s.send("", 0)?;

    Ok(())
}

    
async fn is_public_key_allowed(client: &reqwest::Client, public_key: &str) -> Result<bool, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());

    let data = serde_json::json!({
        "zmq_key": public_key
    });
    let service_url = format!("https://{}", env::var("SERVICE_URL").unwrap_or("https://payment.bitcoinnano.org/api/service-payment/is-active/".to_string()));
    let request = client
        .post(&service_url)
        .headers(headers)
        .json(&data);

    let response = request.send().await?;
    let body: Value = response.json().await?;

    match body.get("active") {
        Some(active) => Ok(active.as_bool().unwrap_or(false)),
        None => Ok(false),
    }
}