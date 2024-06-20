//! Implementation of the `generate_threshold_round1` subcommand
use crate::Error;
use clap::Parser;
use schnorrkel::{olaf::simplpedpop::AllMessage, MiniSecretKey, PublicKey};
use serde_json::from_str;
use std::{
	fs::{self, File},
	io::Write,
	path::Path,
};

/// The `generate_threshold_round1` command
#[derive(Debug, Clone, Parser)]
#[command(name = "generate_threshold_round1", about = "Round 1 of generating a threshold account")]
pub struct GenerateThresholdRound1Cmd {
	/// The minimum number of signers required to sign with the threshold account
	#[clap(long)]
	threshold: u16,
	/// The folder where the files necessary for the execution of the command are located
	#[clap(long)]
	files_path: String,
}

impl GenerateThresholdRound1Cmd {
	/// Run the command
	pub fn run(&self) -> Result<(), Error> {
		let path = Path::new(&self.files_path);

		let secret_key_string = fs::read_to_string(path.join("contributor_secret_key.json"))?;

		let encoded_string: String = serde_json::from_str(&secret_key_string).unwrap();

		let suri = hex::decode(&encoded_string[2..]).unwrap();

		let mut secret_key_bytes = [0; 32];
		secret_key_bytes.copy_from_slice(&suri);

		let keypair = MiniSecretKey::from_bytes(&secret_key_bytes)
			.unwrap()
			.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

		let recipients_string = fs::read_to_string(path.join("recipients.json")).unwrap();

		let recipients_bytes: Vec<String> = from_str(&recipients_string).unwrap();

		let recipients: Vec<PublicKey> = recipients_bytes
			.into_iter()
			.map(|recipient| PublicKey::from_bytes(&hex::decode(&recipient[2..]).unwrap()).unwrap())
			.collect();

		let all_message: AllMessage =
			keypair.simplpedpop_contribute_all(self.threshold, recipients).unwrap();

		let all_message_bytes: Vec<u8> = all_message.to_bytes();

		let all_message_vec: Vec<Vec<u8>> = vec![all_message_bytes];

		let all_message_json = serde_json::to_string_pretty(&all_message_vec).unwrap();

		let mut all_message_file = File::create(path.join("all_messages.json")).unwrap();

		all_message_file.write_all(&all_message_json.as_bytes()).unwrap();

		Ok(())
	}
}
