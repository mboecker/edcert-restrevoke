// The MIT License (MIT)
//
// Copyright (c) 2016 Marvin Böcker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use edcert::revoker::Revoker;
use edcert::revoker::Revokable;
use edcert::revoker::RevokeError;

/// This Revoker can be used for a REST query on the given revokeserver to query, if the
/// Certificate is known to be revoked.
pub struct RestRevoker {
    revokeserver: String
}

impl RestRevoker {

    /// This method creates a new Revoker using the given server address.
    /// The public key will be appended to the URL, so make sure you choose the address
    /// appropriately, eg. you should use "http://www.example.com/?pubkey=" if your serverside
    /// expects a GET parameter called pubkey.
    /// This implementation expects as response a JSON object containing a "revoked" value of either "true"
    /// or "false", but the implementation can be easily changed to what you need.
    pub fn new(revokeserver: &str) -> RestRevoker {
        RestRevoker {
            revokeserver: revokeserver.to_string()
        }
    }
}

impl Revoker for RestRevoker {
    fn is_revoked<T: Revokable>(&self, cert: &T) -> Result<(), RevokeError> {
        use hyper::Client;
        use std::io::Read;
        use rustc_serialize::json::Json;

        // Get the certificate fingerprint.
        let bytestr = cert.fingerprint();

        // create a new hyper client
        let client = Client::new();

        // create the request
        let mut req = client.get(&format!("{}{:?}", self.revokeserver, &bytestr))
                            .send()
                            .expect("Failed to request");

        // allocate a string for the response and read it
        let mut response = String::new();
        req.read_to_string(&mut response).expect("Failed to read response");

        // trim whitespaces
        let response = response.trim();

        // parse JSON
        let json: Result<Json, _> = Json::from_str(response);

        let json: Json = match json {
            Ok(o) => o,
            Err(_) => return Err(RevokeError::ServerUnavailiable),
        };

        // The response must contain a field "revoked"
        let json = match json.find("revoked") {
            Some(o) => o,
            None => return Err(RevokeError::ServerUnavailiable),
        };

        // The response must contain a boolean value in it.
        if json.is_boolean() {
            if json.as_boolean().unwrap() {
                Err(RevokeError::Revoked)
            } else {
                Ok(())
            }
        } else {
            Err(RevokeError::ServerUnavailiable)
        }
    }
}

// #[test]
// fn test_simple() {
//     use edcert::certificate::Certificate;
//     use edcert::meta::Meta;
//     use chrono::UTC;
//
//     let cert = Certificate::generate_random(Meta::new_empty(), UTC::now());
//     let revoker = RestRevoker::new("https://api.rombie.de/v1/is_revoked?public_key=");
//     assert_eq!(true, revoker.is_revoked(&cert).is_ok());
// }
