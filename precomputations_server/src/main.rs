use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use env_logger::Env;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fs::File;
use std::process::Command;

use alloy_primitives::hex;
use alloy_primitives::U256;

#[derive(Debug, Serialize, Deserialize)]
struct PrecomputedBytecode {
    bytecode: String,
}

#[get("/precompute/{x}/{y}")]
async fn precompute(public_key_coords: web::Path<(String, String)>) -> impl Responder {
    let (x, y) = public_key_coords.into_inner();
    format!("Precomputing tables for public key coordinates: x = {x}, y = {y}!");

    let script_base_folder = std::env::var("BASE_FOLDER").unwrap();

    let mut owned_coord: String = x.to_owned();
    let owned_y: String = y.to_owned();
    owned_coord.push_str(&owned_y);

    let mut file_name: String = script_base_folder.to_owned();
    file_name.push_str(&digest(owned_coord));

    let mut script_name: String = script_base_folder.to_owned();
    script_name.push_str(&"precompute.sage");

    let _output = Command::new("sh")
        .arg("-C")
        .arg("./precompute.sh")
        .arg(x)
        .arg(y)
        .arg(file_name.to_owned())
        .arg(script_name.to_owned())
        .status();

    let mut owned_filename: String = file_name.to_owned();
    owned_filename.push_str(&".json");

    let file_open = File::open(owned_filename);

    match file_open {
        Ok(file) => {
            let bytecode: serde_json::Value =
                serde_json::from_reader(file).expect("JSON was not well-formatted");

            let output = bytecode.get("bytecode").unwrap().to_string().to_owned();

            let _delete_command_output = Command::new("sh")
                .arg("-C")
                .arg("./rm.sh")
                .arg(file_name.to_owned())
                .output()
                .unwrap();

            let parsed_output = output[3..output.len() - 1].to_string();

            let final_output = get_init_bytecode(parsed_output);

            HttpResponse::Ok().json(PrecomputedBytecode {
                bytecode: final_output,
            })
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

fn get_init_bytecode(precomputations: String) -> String {
    let init_bytecode_str = "608060405234801561001057600080fd5b5060405161077a38038061077a83398101604081905261002f91610037565b600055610050565b60006020828403121561004957600080fd5b5051919050565b61071b8061005f6000396000f3fe";

    // precomputed from type(KeyPrecomputations).runtimeBytecode
    let runtime_bytecode_hex = hex!("608060405234801561001057600080fd5b50600436106100365760003560e01c8063b5cedec81461003b578063f050fc4e14610063575b600080fd5b61004e61004936600461067c565b61007a565b60405190151581526020015b60405180910390f35b61006c60005481565b60405190815260200161005a565b60006100898383600054610090565b9392505050565b6000823515806100af57506000805160206106c6833981519152833510155b806100bc57506020830135155b806100d957506000805160206106c6833981519152602084013510155b156100e657506000610089565b60006100f56020850135610157565b905060006101276000805160206106c68339815191528388096000805160206106c683398151915284883509866101d0565b90506000805160206106c683398151915285356000805160206106c6833981519152038208159695505050505050565b600061016161065e565b60208152602080820152602060408201528260608201527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f60808201526000805160206106c683398151915260a082015260208160c08360006005600019f16101c957600080fd5b5192915050565b6000806101db61065e565b61010091505b80516000036102765760018203915060c0820386901c6001166080830387901c6001166002026040840388901c6001166004028489901c60011660080260c0860389901c600116601002608087038a901c600116602002604088038b901c600116604002888c901c600116608002010101010101016040028160006006811061026c5761026c6106af565b60200201526101e1565b6040848251018239805192506020810151600180935060fe5b60bf8111156105e257600160601b63ffffffff60c01b031983600209600160601b63ffffffff60c01b0319818209600160601b63ffffffff60c01b0319818909600160601b63ffffffff60c01b03198284099250600160601b63ffffffff60c01b031980600160601b63ffffffff60c01b03198a8c08600160601b63ffffffff60c01b03198b600160601b63ffffffff60c01b0319038d0809600309600160601b63ffffffff60c01b03198685099550600160601b63ffffffff60c01b03198984099850600160601b63ffffffff60c01b031980836002600160601b0363ffffffff60c01b031909600160601b63ffffffff60c01b0319838409089950600160601b63ffffffff60c01b03198083600160601b63ffffffff60c01b0319038c0882099250600160601b63ffffffff60c01b031983600160601b63ffffffff60c01b031989870908965060018d861c1660091b60018d871c16600d1b01905060408503945060018d861c1660081b60018d871c16600c1b018101905060408503945060018d861c1660071b60018d871c16600b1b018101905060408503945060018d861c1660061b60018d871c16600a1b0181019050806104655786600160601b63ffffffff60c01b0319039650505050506105da565b60408b82018939600160601b63ffffffff60c01b031987600160601b63ffffffff60c01b03198860208c015109089150600160601b63ffffffff60c01b03198a600160601b63ffffffff60c01b031903600160601b63ffffffff60c01b03198b8b5109089250600160601b63ffffffff60c01b03198384099050600160601b63ffffffff60c01b03198382099350600160601b63ffffffff60c01b0319818a099250600160601b63ffffffff60c01b03198487099550600160601b63ffffffff60c01b0319818b09600160601b63ffffffff60c01b031980826002600160601b0363ffffffff60c01b031909600160601b63ffffffff60c01b031987600160601b63ffffffff60c01b031903600160601b63ffffffff60c01b031987880908089150600160601b63ffffffff60c01b031980868a09600160601b63ffffffff60c01b031985600160601b63ffffffff60c01b031986600160601b63ffffffff60c01b03190386080908919a5092985095505050505b60bf0161028f565b50505081606082015260208152602080820152602060408201526002600160601b0363ffffffff60c01b03196080820152600160601b63ffffffff60c01b031960a082015260208160c08360006005600019f161063e57600080fd5b80519150600160601b63ffffffff60c01b03198284099695505050505050565b6040518060c001604052806006906020820280368337509192915050565b6000806060838503121561068f57600080fd5b82359150836060840111156106a357600080fd5b50926020919091019150565b634e487b7160e01b600052603260045260246000fdfeffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551a26469706673582212204cd43249ad93606c935ad4e5fae69d4cb359a8563ac399831710cafed075d7f264736f6c63430008140033");

    let init_bytecode_hex = hex!("608060405234801561001057600080fd5b5060405161077a38038061077a83398101604081905261002f91610037565b600055610050565b60006020828403121561004957600080fd5b5051919050565b61071b8061005f6000396000f3fe");

    let precomputation_bytecode_hex = hex::decode(precomputations).unwrap();

    println!("{}", precomputation_bytecode_hex.len());

    // 16384
    let new_runtime_length_hex = format!(
        "{:X}",
        runtime_bytecode_hex.len() + precomputation_bytecode_hex.len()
    );

    let new_constructor_argument_offset = format!(
        "{:X}",
        runtime_bytecode_hex.len() + precomputation_bytecode_hex.len() + init_bytecode_hex.len()
    );

    let init_bytecode_with_new_runtime_length =
        str::replace(&init_bytecode_str, "071b", &new_runtime_length_hex);
    let final_init_bytecode = str::replace(
        init_bytecode_with_new_runtime_length.as_str(),
        "077a",
        &new_constructor_argument_offset,
    );

    let encoded_old_runtime_length = U256::from(runtime_bytecode_hex.len()).to_be_bytes_vec();

    let mut decoded_final_init_bytecode = hex::decode(final_init_bytecode).unwrap();
    decoded_final_init_bytecode.extend(runtime_bytecode_hex.to_vec().into_iter());
    decoded_final_init_bytecode.extend(precomputation_bytecode_hex.into_iter());
    decoded_final_init_bytecode.extend(encoded_old_runtime_length.iter());

    let formatted = hex::encode(&decoded_final_init_bytecode);
    return formatted;
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let host = std::env::var("HOST").unwrap();
    let port = std::env::var("PORT").unwrap().parse().unwrap();

    HttpServer::new(|| App::new().service(precompute))
        .bind((host, port))?
        .run()
        .await
}
