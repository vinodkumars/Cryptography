
var lib = require('./lib');
var sjcl = require('./sjcl');

var tls = require('tls');

var client = function(client_sec_key_base64, client_sec_key_password, ca_cert, name) {
  if (typeof(name) === 'undefined') {
    var name = 'client';
  }
  var client_log = lib.log_with_prefix(name);
  var TYPE = lib.TYPE;

  var socket;
  var protocol_state;

  function unwrap_client_sec_key() {
    var key_enc = lib.base64_to_bitarray(client_sec_key_base64);
    var salt = lib.bitarray_slice(key_enc, 0, 128);
    var key_enc_main = lib.bitarray_slice(key_enc, 128);
    var sk_der = lib.bitarray_slice(lib.KDF(client_sec_key_password, salt), 0, 128);
    var sk_cipher = lib.setup_cipher(sk_der);
    var pair_sec_bits = lib.dec_gcm(sk_cipher, key_enc_main);
    var pair_sec = sjcl.bn.fromBits(pair_sec_bits);
    return new sjcl.ecc['ecdsa'].secretKey(curve, pair_sec);
  }

  function protocol_abort() {
    client_log('protocol error');
    socket.destroy();
    protocol_state = 'ABORT';
  }

  var curve = sjcl.ecc.curves['c256'];

  var client_sec_key = unwrap_client_sec_key();

  var session_callback = null;
  var session_close_callback = null;

  function check_cert(crt) {
    // TODO: implement the X.509 certificate checks
    if(crt.valid_from === undefined || crt.valid_to === undefined || crt.subject === undefined || crt.issuer === undefined || crt.fingerprint === undefined)
    {
        return false;
    }
    var validFrom = new Date(crt.valid_from);
    var validTo = new Date(crt.valid_to);
    var now=new Date();
    if(!((now-validFrom)>0 && (validTo-now)>0))
    {
        return false;
    }
    //client_log("[DIAG] diff: "+(validTo-now));
    //client_log("[DIAG] 7days: "+(7*24*60*60*1000));
    if((validTo-now)<(7*24*60*60*1000))
    {
        return false;
    }
    if(!(crt.subject.C==="US" && crt.subject.ST==="CA" && crt.subject.L==="Stanford" && crt.subject.O==="CS 255" && crt.subject.OU==="Project 3" && crt.subject.CN==="localhost" && crt.subject.emailAddress==="cs255ta@cs.stanford.edu"))
    {
        return false;
    }
    client_log("Certificate validated.");
    return true;
  }

  function process_server_msg(json_data) {
    data = JSON.parse(json_data);
    switch(data.type) {
      case TYPE['CHALLENGE']:
        if (protocol_state != 'START') {
          protocol_abort();
          return;
        }
        protocol_state = 'CHALLENGE';
        // TODO: respond to challenge
        var response = lib.bitarray_to_base64(lib.ECDSA_sign(client_sec_key,lib.string_to_bitarray(data.message)));
        client_log("response: "+response);
        lib.send_message(socket, TYPE['RESPONSE'], response);
        break;

      case TYPE['SESSION_MESSAGE']:
        if (protocol_state != 'SUCCESS') {
          protocol_abort();
          return;
        }
        client_log('received session message: ' + data.message);
        break;

      case TYPE['SUCCESS']:
        if (protocol_state != 'CHALLENGE') {
          protocol_abort();
          return;
        }
        protocol_state = 'SUCCESS';
        if (session_callback != null) {
          session_callback();
        }
        socket.end();
        break;

      default:
        protocol_abort();
        return;
    }
  }

  client = {};

  client.connect = function(host, port, session_callback_f, session_close_callback_f) {
    var client_options = {
      rejectUnauthorized: true,
      // TODO: Fill in options
      ca: ca_cert,
      host: host
    };

    session_callback = session_callback_f;
    socket = tls.connect(port, client_options, function() {
        client_log('connected to server');

            if (!check_cert(socket.getPeerCertificate())) {
            client_log('bad certificate received');
            socket.end();
            protocol_abort();
            }
            protocol_state = 'START';
    });

    socket.setEncoding('utf8');

    socket.on('error', function(msg) {
      client_log(msg);
      protocol_abort();
    });

    socket.on('data', function(msg) {
      process_server_msg(msg)
    });

    socket.on('close', function() {
      protocol_state = 'END';
      client_log('connection closed');

      if (typeof(session_close_callback_f) !== 'undefined') {
        session_close_callback_f();
      }
    });
  }

  client.get_state = function() {
    return protocol_state;
  }

  client.session_send = function(msg) {
    if (protocol_state != 'SUCCESS') {
      throw ("client: tried to send session message in state: " + protocol_state);
    }
    lib.send_message(socket, TYPE['SESSION_MESSAGE'], msg);
    client_log('sent session message: ' + msg);
  }
  
  client.disconnect = function() {
    protocol_state = 'END';
    socket.end();
  }

  return client;
}

module.exports.client = client;
