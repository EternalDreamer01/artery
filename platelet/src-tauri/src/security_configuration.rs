use std::process::Command;

use crate::misc::create_folder_if_not_exist;

pub enum SecurityConfigurationError {
    CantCreateCertificate(String),
    Unknown(String),
}

pub struct SecurityConfiguration {
    root_authority_number: u64,
    aa_per_root: u64,
    ticket_per_aa: u64,
}

impl SecurityConfiguration {
    pub fn new(
        root_authority_number: u64,
        aa_per_root: u64,
        ticket_per_aa: u64,
    ) -> SecurityConfiguration {
        SecurityConfiguration {
            root_authority_number,
            aa_per_root,
            ticket_per_aa,
        }
    }

    fn generate_root_authority(
        root_number: u64,
        scenario_path: &str,
    ) -> Result<(), SecurityConfigurationError> {
        create_folder_if_not_exist(scenario_path.to_owned() + "certificate/roots");

        // FIXME: Remove unwrap and replace by handling error return
        let key_path = scenario_path.to_owned()
            + "/certificate/roots/root"
            + &root_number.to_string()
            + ".key";
        let cert_path = scenario_path.to_owned()
            + "/certificate/roots/root"
            + &root_number.to_string()
            + ".cert";

        Command::new("certify")
            .args(["generate-key", key_path.as_str()])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();

        Command::new("certify")
            .args([
                "generate-root",
                "--output",
                cert_path.as_str(),
                "--subject-key",
                key_path.as_str(),
            ])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();

        Ok(())
    }

    fn generate_authorization_authority(
        root_number: u64,
        aa_number: u64,
        scenario_path: &str,
    ) -> Result<(), SecurityConfigurationError> {
        create_folder_if_not_exist(scenario_path.to_owned() + "/certificate/aas");

        let root_key_path =
            scenario_path.to_owned() + "/certificate/root/root" + &root_number.to_string() + ".key";
        let root_cert_path = scenario_path.to_owned()
            + "/certificate/root/root"
            + &root_number.to_string()
            + ".cert";
        let key_path = scenario_path.to_owned()
            + "/certificate/aas/aa"
            + &root_number.to_string()
            + &aa_number.to_string()
            + ".key";
        let cert_path = scenario_path.to_owned()
            + "/certificate/aas/aa"
            + &root_number.to_string()
            + &aa_number.to_string()
            + ".cert";

        Command::new("certify")
            .args(["generate-key", key_path.as_str()])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();

        Command::new("certify")
            .args([
                "generate-aa",
                "--output",
                cert_path.as_str(),
                "--sign-key",
                root_key_path.as_str(),
                "--sign-cert",
                root_cert_path.as_str(),
                "--subject-key",
                key_path.as_str(),
            ])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();

        Ok(())
    }

    fn generate_ticket(
        root_number: u64,
        aa_number: u64,
        ticket_number: u64,
        scenario_path: &str,
    ) -> Result<(), SecurityConfigurationError> {
        create_folder_if_not_exist(scenario_path.to_owned() + "/certificate/tickets");

        let aa_key_path = scenario_path.to_owned()
            + "/certificate/aas/aa"
            + &root_number.to_string()
            + &aa_number.to_string()
            + ".key";
        let aa_cert_path = scenario_path.to_owned()
            + "/certificate/aas/aa"
            + &root_number.to_string()
            + &aa_number.to_string()
            + ".cert";
        let key_path = scenario_path.to_owned()
            + "/certificate/tickets/ticket"
            + &root_number.to_string()
            + &aa_number.to_string()
            + &ticket_number.to_string()
            + ".key";
        let cert_path = scenario_path.to_owned()
            + "/certificate/tickets/ticket"
            + &root_number.to_string()
            + &aa_number.to_string()
            + &ticket_number.to_string()
            + ".cert";

        Command::new("certify")
            .args(["generate-key", key_path.as_str()])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();

        Command::new("certify")
            .args([
                "generate-ticket",
                "--output",
                cert_path.as_str(),
                "--sign-key",
                aa_key_path.as_str(),
                "--sign-cert",
                aa_cert_path.as_str(),
                "--subject-key",
                key_path.as_str(),
            ])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();

        Ok(())
    }

    // TODO: Maybe replace all this by using linking certify C shared lib code instead of calling the binary
    pub fn generate_certificates(
        &self,
        scenario_path: String,
    ) -> Result<(), SecurityConfigurationError> {
        create_folder_if_not_exist(scenario_path.to_owned() + "certificate")
            .map_err(|e| SecurityConfigurationError::Unknown(e.to_string()))?;

        for root_number in 0..self.root_authority_number {
            Self::generate_root_authority(root_number, &scenario_path)?;

            for aa_number in 0..self.aa_per_root {
                Self::generate_authorization_authority(root_number, aa_number, &scenario_path)?;

                for ticket_number in 0..self.ticket_per_aa {
                    Self::generate_ticket(root_number, aa_number, ticket_number, &scenario_path)?;
                }
            }
        }

        Ok(())
    }
}
