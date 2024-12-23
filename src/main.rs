use actix_web::{get, post, put, web, App, HttpResponse, HttpServer, Responder};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::{Config, Pool, Runtime};
use rand::thread_rng;
use rand::Rng;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tokio_postgres::NoTls;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Deserialize, Debug)]
struct UpdateUserInfo {
    private_key: String,
    name: Option<String>,
    email: Option<String>,
    phone_number: Option<String>,
    gpg_fingerprint: Option<String>,
}

#[derive(Deserialize, Debug)] 
struct RegisterUserInfo {
    name: Option<String>,
    email: Option<String>,
    phone_number: Option<String>,
    gpg_fingerprint: Option<String>,
}

struct AppState {
    db: DatabaseConfig,
}

struct DatabaseConfig {
    pool: Pool,
}

#[derive(Serialize, Deserialize, Debug)]
struct IdentityProof {
    id: Uuid,
    user_id: Uuid,
    emoji_sequence: String,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct CreateProofRequest {
    private_key: String,
}

#[derive(Deserialize)]
struct VerifyProofRequest {
    public_key: String,
    emoji_sequence: String,
}

const CREATE_USERS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        public_key TEXT NOT NULL UNIQUE,
        private_key_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        name TEXT,
        email TEXT,
        phone_number TEXT,
        gpg_fingerprint TEXT
    )
";

const CREATE_IDENTITY_PROOFS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS identity_proofs (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id),
        emoji_sequence TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL
    )
";

impl DatabaseConfig {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut cfg = Config::new();
        cfg.dbname = Some("nichokas_EmojiUtils".to_string());

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;

        let client = pool.get().await?;

        client.execute(CREATE_USERS_TABLE, &[]).await?;
        client.execute(CREATE_IDENTITY_PROOFS_TABLE, &[]).await?;

        Ok(DatabaseConfig { pool })
    }

    async fn save_user(&self, user: &User) -> Result<(), Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        let result = client.execute(
            "INSERT INTO users (id, public_key, private_key_hash, salt, name, email, phone_number, gpg_fingerprint)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &user.id,
                &user.public_key,
                &user.private_key_hash,
                &user.salt,
                &user.name,
                &user.email,
                &user.phone_number,
                &user.gpg_fingerprint,
            ],
        ).await?;

        Ok(())
    }

    async fn find_user_by_public_key(
        &self,
        public_key: &str,
    ) -> Result<Option<User>, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt("SELECT * FROM users WHERE public_key = $1", &[&public_key])
            .await?;

        Ok(row.map(|row| User {
            id: row.get("id"),
            public_key: row.get("public_key"),
            private_key_hash: row.get("private_key_hash"),
            salt: row.get("salt"),
            name: row.get("name"),
            email: row.get("email"),
            phone_number: row.get("phone_number"),
            gpg_fingerprint: row.get("gpg_fingerprint"),
        }))
    }

    async fn update_user(&self, user: &User) -> Result<bool, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE users SET
                name = COALESCE($1, name),
                email = COALESCE($2, email),
                phone_number = COALESCE($3, phone_number),
                gpg_fingerprint = COALESCE($4, gpg_fingerprint)
             WHERE id = $5",
                &[
                    &user.name,
                    &user.email,
                    &user.phone_number,
                    &user.gpg_fingerprint,
                    &user.id,
                ],
            )
            .await?;

        Ok(result > 0)
    }
    async fn create_identity_proof(
        &self,
        user_id: Uuid,
    ) -> Result<IdentityProof, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        // Limpiar pruebas antiguas
        client
            .execute(
                "DELETE FROM identity_proofs WHERE created_at < $1",
                &[&(Utc::now() - Duration::minutes(5))],
            )
            .await?;

        // Generar secuencia hexadecimal de 10 caracteres
        let hex_sequence = generate_hex_sequence(10);
        println!("Secuencia hexadecimal generada: {}", hex_sequence);

        let proof = IdentityProof {
            id: Uuid::new_v4(),
            user_id,
            emoji_sequence: hex_sequence.clone(),
            created_at: Utc::now(),
        };

        client
            .execute(
                "INSERT INTO identity_proofs (id, user_id, emoji_sequence, created_at) 
             VALUES ($1, $2, $3, $4)",
                &[
                    &proof.id,
                    &proof.user_id,
                    &proof.emoji_sequence,
                    &proof.created_at,
                ],
            )
            .await?;

        Ok(proof)
    }
    async fn verify_identity_proof(
        &self,
        public_key: &str,
        emoji_sequence: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        println!("Verificando en DB:");
        println!("Public key: {}", public_key);
        println!("Emoji sequence a verificar: {}", emoji_sequence);

        let five_minutes_ago = Utc::now() - Duration::minutes(5);

        let row = client
            .query_opt(
                "SELECT p.* FROM identity_proofs p
             JOIN users u ON p.user_id = u.id
             WHERE u.public_key = $1 
             AND p.emoji_sequence = $2 
             AND p.created_at > $3",
                &[&public_key, &emoji_sequence, &five_minutes_ago],
            )
            .await?;

        if let Some(row) = &row {
            println!("Encontrada prueba de identidad:");
            println!(
                "Emoji sequence en DB: {}",
                row.get::<_, String>("emoji_sequence")
            );
        } else {
            println!("No se encontró prueba de identidad válida");
        }

        Ok(row.is_some())
    }
    async fn find_user_by_private_key(
        &self,
        private_key: &str,
    ) -> Result<Option<User>, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        let rows = client.query("SELECT * FROM users", &[]).await?;

        for row in rows {
            let user = User {
                id: row.get("id"),
                public_key: row.get("public_key"),
                private_key_hash: row.get("private_key_hash"),
                salt: row.get("salt"),
                name: row.get("name"),
                email: row.get("email"),
                phone_number: row.get("phone_number"),
                gpg_fingerprint: row.get("gpg_fingerprint"),
            };

            if verify_private_key(private_key, &user.private_key_hash) {
                return Ok(Some(user));
            }
        }

        Ok(None)
    }
}

fn hash_private_key(private_key: &str) -> (String, String) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(private_key.as_bytes(), &salt)
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
    let pkcs8_bytes =
        Ed25519KeyPair::generate_pkcs8(&rng).expect("Error al generar el par de claves");
    let key_pair =
        Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("Error al crear el par de claves");

    // Codifica las claves en base64
    let public_key = general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
    let private_key = general_purpose::STANDARD.encode(pkcs8_bytes.as_ref());

    // Genera el hash y salt para la private key
    let (private_key_hash, salt) = hash_private_key(&private_key);

    // Retorna (public_key, private_key, private_key_hash, salt)
    (public_key, private_key, private_key_hash, salt)
}

fn generate_hex_sequence(length: usize) -> String {
    let mut rng = thread_rng();
    let hex_chars: Vec<char> = "0123456789ABCDEF".chars().collect();

    (0..length)
        .map(|_| hex_chars[rng.gen_range(0..16)])
        .collect()
}

#[post("/register")]
async fn register_user(
    data: web::Data<AppState>,
    user_info: web::Json<RegisterUserInfo>,
) -> impl Responder {
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

    match data.db.save_user(&user).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "public_key": public_key,
            "private_key": private_key
        })),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Error al registrar usuario: {}", e))
        }
    }
}

#[get("/user_info/{public_key}")]
async fn get_user_info(data: web::Data<AppState>, public_key: web::Path<String>) -> impl Responder {
    let decoded_key = match urlencoding::decode(public_key.as_ref()) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => public_key.to_string(),
    };

    match data.db.find_user_by_public_key(&decoded_key).await {
        Ok(Some(user)) => {
            let response = serde_json::json!({
                "id": user.id,
                "public_key": user.public_key,
                "name": user.name,
                "email": user.email,
                "phone_number": user.phone_number,
                "gpg_fingerprint": user.gpg_fingerprint
            });
            HttpResponse::Ok().json(response)
        }
        Ok(None) => HttpResponse::NotFound().body("Usuario no encontrado"),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Error al buscar usuario: {}", e))
        }
    }
}
#[put("/update_user_info")]
async fn update_user_info(
    data: web::Data<AppState>,
    new_info: web::Json<UpdateUserInfo>,
) -> impl Responder {
    let mut found_user = None;

    if let Ok(client) = data.db.pool.get().await {
        if let Ok(rows) = client.query("SELECT * FROM users", &[]).await {
            for row in rows {
                let user = User {
                    id: row.get("id"),
                    public_key: row.get("public_key"),
                    private_key_hash: row.get("private_key_hash"),
                    salt: row.get("salt"),
                    name: row.get("name"),
                    email: row.get("email"),
                    phone_number: row.get("phone_number"),
                    gpg_fingerprint: row.get("gpg_fingerprint"),
                };

                if verify_private_key(&new_info.private_key, &user.private_key_hash) {
                    found_user = Some(user);
                    break;
                }
            }
        }
    }

    if let Some(mut user) = found_user {
        // Solo actualizar los campos que se proporcionaron en la solicitud
        if let Some(name) = &new_info.name {
            user.name = Some(name.clone());
        }
        if let Some(email) = &new_info.email {
            user.email = Some(email.clone());
        }
        if let Some(phone_number) = &new_info.phone_number {
            user.phone_number = Some(phone_number.clone());
        }
        if let Some(gpg_fingerprint) = &new_info.gpg_fingerprint {
            user.gpg_fingerprint = Some(gpg_fingerprint.clone());
        }

        // Actualizar en la base de datos
        match data.db.update_user(&user).await {
            Ok(true) => HttpResponse::Ok().body("Info successfully updated"),
            Ok(false) => HttpResponse::NotFound().body("User not found"),
            Err(e) => HttpResponse::InternalServerError()
                .body(format!("Error while updating the user: {}", e)),
        }
    } else {
        HttpResponse::Unauthorized().body("Failed auth")
    }
}

#[post("/create_identity_proof")]
async fn create_identity_proof(
    data: web::Data<AppState>,
    req: web::Json<CreateProofRequest>,
) -> impl Responder {
    match data.db.find_user_by_private_key(&req.private_key).await {
        Ok(Some(user)) => match data.db.create_identity_proof(user.id).await {
            Ok(proof) => HttpResponse::Ok().json(proof),
            Err(e) => {
                eprintln!("Error al crear prueba de identidad: {}", e);
                HttpResponse::InternalServerError().body("Error al crear prueba de identidad")
            }
        },
        Ok(None) => HttpResponse::Unauthorized().body("Autenticación fallida"),
        Err(e) => {
            eprintln!("Error al buscar usuario: {}", e);
            HttpResponse::InternalServerError().body("Error al buscar usuario")
        }
    }
}

#[post("/verify_identity")]
async fn verify_identity(
    data: web::Data<AppState>,
    req: web::Json<VerifyProofRequest>,
) -> impl Responder {
    println!("Recibiendo verificación:");
    println!("Public key: {}", req.public_key);
    println!(
        "Emoji sequence (bytes): {:?}",
        req.emoji_sequence.as_bytes()
    );
    println!("Emoji sequence (chars): {}", req.emoji_sequence);

    match data
        .db
        .verify_identity_proof(&req.public_key, &req.emoji_sequence)
        .await
    {
        Ok(true) => {
            println!("Verificación exitosa");
            HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({
                    "verified": true,
                    "message": "Identidad verificada correctamente"
                }))
        }
        Ok(false) => {
            println!("Verificación fallida");
            HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({
                    "verified": false,
                    "message": "Secuencia inválida o expirada"
                }))
        }
        Err(e) => {
            eprintln!("Error en verificación: {}", e);
            HttpResponse::InternalServerError()
                .content_type("application/json")
                .json(serde_json::json!({
                    "error": format!("Error en verificación: {}", e)
                }))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Iniciando servidor...");

    let db_config = match DatabaseConfig::new().await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error al conectar a la base de datos: {}", e);
            return Ok(());
        }
    };

    let app_state = web::Data::new(AppState { db: db_config });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(register_user)
            .service(get_user_info)
            .service(update_user_info)
            .service(create_identity_proof)
            .service(verify_identity)
    })
    .bind("127.0.0.1:8901")?
    .run()
    .await
}
