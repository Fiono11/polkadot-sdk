//! Implementation of the `sign_threshold_round2` subcommand
use crate::Error;
use clap::Parser;
use color_eyre::eyre::eyre;
use scale_value::{Composite, Value, ValueDef};
use schnorrkel::olaf::{
	frost::{SigningCommitments, SigningNonces},
	simplpedpop::SPPOutputMessage,
	SigningKeypair,
};
use serde_json::from_str;
use std::{
	fs::{self, File},
	io::Write,
	path::Path,
	str::FromStr,
};
use subxt::{
	backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
	config::polkadot::PolkadotExtrinsicParamsBuilder,
	tx,
	utils::AccountId32,
	OnlineClient, PolkadotConfig,
};

/// The `sign_threshold_round2` command
#[derive(Debug, Clone, Parser)]
#[command(name = "sign_threshold_round2", about = "Round 2 of signing a threshold account")]
pub struct SignThresholdRound2Cmd {
	/// The folder where the files necessary for the execution of the command are located
	#[clap(long)]
	files_path: String,
	#[clap(long)]
	context: String,
	#[clap(long)]
	url: Option<String>,
	#[clap(long)]
	pallet: String,
	#[clap(long)]
	call: String,
	#[clap(required = false)]
	trailing_args: Vec<String>,
}

impl SignThresholdRound2Cmd {
	/// Run the command
	pub async fn run(&self) -> Result<(), Error> {
		let path = Path::new(&self.files_path);

		let signing_commitments_string =
			fs::read_to_string(path.join("signing_commitments.json")).unwrap();

		let signing_commitments_bytes: Vec<Vec<u8>> =
			from_str(&signing_commitments_string).unwrap();

		let signing_commitments: Vec<SigningCommitments> = signing_commitments_bytes
			.iter()
			.map(|signing_commitments| SigningCommitments::from_bytes(signing_commitments).unwrap())
			.collect();

		let signing_nonces_string = fs::read_to_string(path.join("signing_nonces.json")).unwrap();

		let signing_nonces_bytes: Vec<u8> = from_str(&signing_nonces_string).unwrap();

		let signing_nonces = SigningNonces::from_bytes(&signing_nonces_bytes).unwrap();

		let signing_share_string = fs::read_to_string(path.join("signing_share.json")).unwrap();

		let signing_share_bytes: Vec<u8> = from_str(&signing_share_string).unwrap();

		let signing_share = SigningKeypair::from_bytes(&signing_share_bytes).unwrap();

		let output_string = fs::read_to_string(path.join("spp_output.json")).unwrap();

		let output_bytes: Vec<u8> = from_str(&output_string).unwrap();

		let spp_output = SPPOutputMessage::from_bytes(&output_bytes).unwrap();

		let client = OnlineClient::<PolkadotConfig>::new().await.unwrap();

		let rpc_client = match &self.url {
			Some(url) => RpcClient::from_url(url).await.unwrap(),
			None => RpcClient::from_url("ws://127.0.0.1:9944").await.unwrap(),
		};

		let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);

		let threshold_public_key_string =
			fs::read_to_string(path.join("threshold_public_key.json")).unwrap();

		let account_id =
			AccountId32::from_str(from_str(&threshold_public_key_string).unwrap()).unwrap();

		let nonce = legacy_rpc.system_account_next_index(&account_id).await.unwrap();

		let params = PolkadotExtrinsicParamsBuilder::new().nonce(nonce).build();

		// collect all the trailing arguments into a single string that is later into a scale_value::Value
		let trailing_args = self.trailing_args.join(" ");

		let pallet_name = self.pallet.to_string();

		// parse scale_value from trailing arguments and try to create an unsigned extrinsic with it:
		let value = parse_string_into_scale_value(&trailing_args).unwrap();
		let value_as_composite = value_into_composite(value);

		let call_name = self.call.to_string();

		let call = tx::dynamic(pallet_name, call_name, value_as_composite);

		let partial_tx = client.tx().create_partial_signed_offline(&call, params).unwrap();

		let payload = partial_tx.signer_payload();

		let signing_package = signing_share
			.sign(
				self.context.clone().into_bytes(),
				payload,
				spp_output.spp_output(),
				signing_commitments,
				&signing_nonces,
			)
			.unwrap();

		let signing_packages_vec = vec![signing_package.to_bytes()];

		let signing_package_json = serde_json::to_string_pretty(&signing_packages_vec).unwrap();

		let mut signing_package_file = File::create(path.join("signing_packages.json")).unwrap();

		signing_package_file.write_all(&signing_package_json.as_bytes()).unwrap();

		Ok(())
	}
}

pub fn parse_string_into_scale_value(str: &str) -> color_eyre::Result<Value> {
	let value = scale_value::stringify::from_str(str).0.map_err(|err| {
        eyre!(
            "scale_value::stringify::from_str led to a ParseError.\n\ntried parsing: \"{str}\"\n\n{err}",
        )
    })?;
	Ok(value)
}

/// composites stay composites, all other types are converted into a 1-fielded unnamed composite
pub(crate) fn value_into_composite(value: scale_value::Value) -> scale_value::Composite<()> {
	match value.value {
		ValueDef::Composite(composite) => composite,
		_ => Composite::Unnamed(vec![value]),
	}
}
