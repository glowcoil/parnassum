use ring::{digest, pbkdf2};

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
pub const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
const PBKDF2_ITERATIONS: u32 = 100_000;
const DB_SALT_COMPONENT: [u8; 16] = [
    0x0f, 0x3f, 0xca, 0xda, 0x4f, 0xde, 0xe0, 0xbd,
    0x65, 0x0d, 0xcc, 0xf1, 0xb1, 0xb7, 0xc5, 0x05,
];

pub fn hash_password(password: &str, user_salt: &[u8], hashed: &mut [u8]) {
    let mut salt = Vec::with_capacity(DB_SALT_COMPONENT.len() + user_salt.len());
    salt.extend(DB_SALT_COMPONENT.as_ref());
    salt.extend(user_salt);
    pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERATIONS, &salt, password.as_bytes(), hashed);
}

// pub fn verify_password(&self, username: &str, attempted_password: &str)
//                        -> Result<(), Error> {
//     match self.storage.get(username) {
//        Some(actual_password) => {
//            let salt = self.salt(username);
//            pbkdf2::verify(DIGEST_ALG, PBKDF2_ITERATIONS, &salt,
//                           attempted_password.as_bytes(),
//                           actual_password)
//                 .map_err(|_| Error::WrongUsernameOrPassword)
//        },

//        None => Err(Error::WrongUsernameOrPassword)
//     }
// }

// fn salt(&self, username: &str) -> Vec<u8> {
//     let mut salt = Vec::with_capacity(DB_SALT_COMPONENT.len() +
//                                       username.as_bytes().len());
//     salt.extend(DB_SALT_COMPONENT.as_ref());
//     salt.extend(username.as_bytes());
//     salt
// }
