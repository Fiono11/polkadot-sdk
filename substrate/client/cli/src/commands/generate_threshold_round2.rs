//! Implementation of the `generate_threshold_round2` subcommand
use crate::Error;
use clap::Parser;
use schnorrkel::{olaf::simplpedpop::AllMessage, MiniSecretKey};
use serde_json::from_str;
use sp_runtime::AccountId32;
use std::{
	fs::{self, File},
	io::Write,
	path::Path,
};

/// The `generate_threshold_round2` command
#[derive(Debug, Clone, Parser)]
#[command(name = "generate_threshold_round2", about = "Round 2 of generating a threshold account")]
pub struct GenerateThresholdRound2Cmd {
	/// The folder where the files necessary for the execution of the command are located
	#[clap(long)]
	files_path: String,
}

impl GenerateThresholdRound2Cmd {
	/// Run the command
	pub fn run(&self) -> Result<(), Error> {
		let path = Path::new(&self.files_path);

		let secret_key_string = fs::read_to_string(path.join("recipient_secret_key.json"))?;

		let encoded_string: String = serde_json::from_str(&secret_key_string).unwrap();

		let suri = hex::decode(&encoded_string[2..]).unwrap();

		let mut secret_key_bytes = [0; 32];
		secret_key_bytes.copy_from_slice(&suri);

		let keypair = MiniSecretKey::from_bytes(&secret_key_bytes)
			.unwrap()
			.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

		let all_messages_string = fs::read_to_string(path.join("all_messages.json")).unwrap();

		let all_messages_bytes: Vec<Vec<u8>> = from_str(&all_messages_string).unwrap();

		let all_messages: Vec<AllMessage> = all_messages_bytes
			.iter()
			.map(|all_message| AllMessage::from_bytes(all_message).unwrap())
			.collect();

		let simplpedpop = keypair.simplpedpop_recipient_all(&all_messages).unwrap();

		let spp_output = simplpedpop.0.clone();

		let output_json = serde_json::to_string_pretty(&spp_output.to_bytes()).unwrap();

		let mut output_file = File::create(path.join("spp_output.json")).unwrap();

		output_file.write_all(&output_json.as_bytes()).unwrap();

		let signing_share = simplpedpop.1;

		let signing_share_json =
			serde_json::to_string_pretty(&signing_share.to_bytes().to_vec()).unwrap();

		let mut signing_share_file = File::create(path.join("signing_share.json")).unwrap();

		signing_share_file.write_all(&signing_share_json.as_bytes()).unwrap();

		let threshold_public_key =
			AccountId32::new(simplpedpop.0.spp_output().threshold_public_key().0.to_bytes());

		let threshold_public_key_json =
			serde_json::to_string_pretty(&threshold_public_key).unwrap();

		let mut threshold_public_key_file =
			File::create(path.join("threshold_public_key.json")).unwrap();

		threshold_public_key_file
			.write_all(threshold_public_key_json.as_bytes())
			.unwrap();

		Ok(())
	}
}
