use actix_web::{web, App, HttpResponse, HttpServer, Responder, post, get, put};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::{SystemRandom};
use base64::{engine::general_purpose, Engine};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

#[derive(Serialize, Deserialize, Clone)]
struct User {
    id: Uuid,
    public_key: String,
    private_key_hash: String, 
    salt: String,             
    name: Option<String>,
    email: Option<String>,
    phone_number: Option<String>,
    gpg_fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct UpdateUserInfo {
    private_key: String,
    name: Option<String>,
    email: Option<String>,
    phone_number: Option<String>,
    gpg_fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct RegisterUserInfo {
    name: Option<String>,
    email: Option<String>,
    phone_number: Option<String>,
    gpg_fingerprint: Option<String>,
}

struct AppState {
    users: Mutex<Vec<User>>,
}


fn hash_private_key(private_key: &str) -> (String, String) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(private_key.as_bytes(), &salt)
        .unwrap()
        .to_string();

    (password_hash, salt.to_string())
}

fn verify_private_key(private_key: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    Argon2::default()
        .verify_password(private_key.as_bytes(), &parsed_hash)
        .is_ok()
}

fn generate_key_pair() -> (String, String, String, String) {
    // Genera el par de claves original
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).expect("Error al generar el par de claves");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("Error al crear el par de claves");

    // Codifica las claves en base64
    let public_key = general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
    let private_key = general_purpose::STANDARD.encode(pkcs8_bytes.as_ref());

    // Genera el hash y salt para la private key
    let (private_key_hash, salt) = hash_private_key(&private_key);

    // Retorna (public_key, private_key, private_key_hash, salt)
    (public_key, private_key, private_key_hash, salt)
}

// Y luego modifica el endpoint de registro así:
#[post("/register")]
async fn register_user(
    data: web::Data<AppState>,
    user_info: web::Json<RegisterUserInfo>,
) -> impl Responder {
    let mut users = data.users.lock().unwrap();

    // Genera el par de claves y el hash
    let (public_key, private_key, private_key_hash, salt) = generate_key_pair();

    let user = User {
        id: Uuid::new_v4(),
        public_key: public_key.clone(),
        private_key_hash,
        salt,
        name: user_info.name.clone(),
        email: user_info.email.clone(),
        phone_number: user_info.phone_number.clone(),
        gpg_fingerprint: user_info.gpg_fingerprint.clone(),
    };

    users.push(user);
    
    // private key on plain text should only be used at here
    HttpResponse::Ok().json(
        serde_json::json!({
            "public_key": public_key,
            "private_key": private_key
        })
    )
}

#[get("/user_info/{public_key}")]
async fn get_user_info(
    data: web::Data<AppState>,
    public_key: web::Path<String>,
) -> impl Responder {
    let users = data.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.public_key == *public_key) {
        let response = serde_json::json!({
            "id": user.id,
            "public_key": user.public_key,
            "name": user.name,
            "email": user.email,
            "phone_number": user.phone_number,
            "gpg_fingerprint": user.gpg_fingerprint
        });
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::NotFound().body("Usuario no encontrado")
    }
}

#[put("/update_user_info")]
async fn update_user_info(
    data: web::Data<AppState>,
    new_info: web::Json<UpdateUserInfo>,
) -> impl Responder {
    let mut users = data.users.lock().unwrap();

    // Encuentra el usuario y verifica la private key
    if let Some(user) = users.iter_mut().find(|u| {
        verify_private_key(&new_info.private_key, &u.private_key_hash)
    }) {
        user.name = new_info.name.clone();
        user.email = new_info.email.clone();
        user.phone_number = new_info.phone_number.clone();
        user.gpg_fingerprint = new_info.gpg_fingerprint.clone();
        HttpResponse::Ok().body("Información actualizada")
    } else {
        HttpResponse::Unauthorized().body("Autenticación fallida")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_state = web::Data::new(AppState {
        users: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(register_user)
            .service(get_user_info)
            .service(update_user_info)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
