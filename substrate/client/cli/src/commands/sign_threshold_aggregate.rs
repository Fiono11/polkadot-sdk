//! Implementation of the `sign_threshold_round2` subcommand
use crate::{
	commands::sign_threshold_round2::{parse_string_into_scale_value, value_into_composite},
	Error,
};
use clap::Parser;
use schnorrkel::olaf::frost::{aggregate, SigningPackage};
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
	utils::{AccountId32, MultiSignature},
	OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519;

/// The `sign_threshold_aggregate` command
#[derive(Debug, Clone, Parser)]
#[command(
	name = "sign_threshold_aggregate",
	about = "Aggregate the partial signatures to form the threshold signature of a threshold account"
)]
pub struct SignThresholdAggregateCmd {
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

impl SignThresholdAggregateCmd {
	/// Run the command
	pub async fn run(&self) -> Result<(), Error> {
		let path = Path::new(&self.files_path);

		let threshold_public_key_string =
			fs::read_to_string(path.join("threshold_public_key.json")).unwrap();

		let account_id =
			AccountId32::from_str(from_str(&threshold_public_key_string).unwrap()).unwrap();

		let signing_packages_string =
			fs::read_to_string(path.join("signing_packages.json")).unwrap();

		let signing_packages_bytes: Vec<Vec<u8>> = from_str(&signing_packages_string).unwrap();

		let signing_packages: Vec<SigningPackage> = signing_packages_bytes
			.iter()
			.map(|signing_commitments| SigningPackage::from_bytes(signing_commitments).unwrap())
			.collect();

		let group_signature = aggregate(&signing_packages).unwrap();

		let signature_json =
			serde_json::to_string_pretty(&group_signature.to_bytes().to_vec()).unwrap();

		let mut signature_file = File::create(path.join("signature.json")).unwrap();

		signature_file.write_all(&signature_json.as_bytes()).unwrap();

		let client = OnlineClient::<PolkadotConfig>::new().await.unwrap();

		let rpc_client = match &self.url {
			Some(url) => RpcClient::from_url(url).await.unwrap(),
			None => RpcClient::from_url("ws://127.0.0.1:9944").await.unwrap(),
		};

		let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);

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

		let signature = sr25519::Signature(group_signature.to_bytes());

		let tx = partial_tx.sign_with_address_and_signature(
			&account_id.into(),
			&MultiSignature::Sr25519(signature.0),
		);

		tx.submit().await.unwrap();

		Ok(())
	}
}
