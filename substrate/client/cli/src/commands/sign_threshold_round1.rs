//! Implementation of the `sign_threshold_round1` subcommand
use crate::Error;
use clap::Parser;
use schnorrkel::olaf::SigningKeypair;
use serde_json::from_str;
use std::{
	fs::{self, File},
	io::Write,
	path::Path,
};

/// The `sign_threshold_round1` command
#[derive(Debug, Clone, Parser)]
#[command(name = "sign_threshold_round1", about = "Round 1 of signing a threshold account")]
pub struct SignThresholdRound1Cmd {
	/// The folder where the files necessary for the execution of the command are located
	#[clap(long)]
	files_path: String,
}

impl SignThresholdRound1Cmd {
	/// Run the command
	pub fn run(&self) -> Result<(), Error> {
		let path = Path::new(&self.files_path);

		let signing_share_string = fs::read_to_string(path.join("signing_share.json")).unwrap();

		let signing_share_bytes: Vec<u8> = from_str(&signing_share_string).unwrap();

		let signing_share = SigningKeypair::from_bytes(&signing_share_bytes).unwrap();

		let (signing_nonces, signing_commitments) = signing_share.commit();

		let signing_nonces_json =
			serde_json::to_string_pretty(&signing_nonces.to_bytes().to_vec()).unwrap();

		let mut signing_nonces_file = File::create(path.join("signing_nonces.json")).unwrap();

		signing_nonces_file.write_all(&signing_nonces_json.as_bytes()).unwrap();

		let signing_commitments_vec = vec![signing_commitments.to_bytes().to_vec()];

		let signing_commitments_json =
			serde_json::to_string_pretty(&signing_commitments_vec).unwrap();

		let mut signing_commitments_file =
			File::create(path.join("signing_commitments.json")).unwrap();

		signing_commitments_file
			.write_all(&signing_commitments_json.as_bytes())
			.unwrap();

		Ok(())
	}
}
