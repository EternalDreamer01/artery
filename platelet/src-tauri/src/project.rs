use std::{
    error::Error,
    fs::{create_dir, File},
    io::{Read, Write},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{artery_configuration_builder::ArteryConfigurationBuilder, misc::folder_exist};
#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("Can't save project settings: {0}")]
    Save(String),
    #[error("Can't load project settings: {0}")]
    Load(String),
    #[error("Can't build artery configuration file: {0}")]
    BuildArteryConfiguration(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Project {
    pub project_name: String,
    pub artery_path: String,
    pub map_path: Option<String>,
    pub vehicle_number: u64,
    pub certificate_number: u64,
}

impl Project {
    pub fn new(project_name: String, artery_path: String) -> Project {
        Project {
            project_name,
            artery_path,
            map_path: None,
            vehicle_number: 0,
            certificate_number: 0,
        }
    }

    pub fn save_project_settings(&self) -> Result<(), ProjectError> {
        let project_path: String = format!("{}/scenarios/{}", self.artery_path, self.project_name);
        if !folder_exist(project_path.to_owned()) {
            create_dir(project_path.to_owned()).map_err(|e| ProjectError::Save(e.to_string()))?;
        }
        let mut f = File::create(format!("{}/{}.platelet", project_path, self.project_name))
            .map_err(|e| ProjectError::Save(e.to_string()))?;

        f.write_all(
            serde_json::to_string(self)
                .map_err(|e| ProjectError::Save(e.to_string()))?
                .as_bytes(),
        )
        .map_err(|e| ProjectError::Save(e.to_string()))?;

        Ok(())
    }

    pub fn load_project_settings(Project_settings_path: String) -> Result<Project, ProjectError> {
        let mut f =
            File::open(Project_settings_path).map_err(|e| ProjectError::Load(e.to_string()))?;

        let mut settings = String::new();
        f.read_to_string(&mut settings)
            .map_err(|e| ProjectError::Load(e.to_string()))?;

        match serde_json::from_str(&settings) {
            Ok(project) => Ok(project),
            Err(e) => Err(ProjectError::Load(e.to_string())),
        }
    }

    pub fn build_project_artery_configuration(&self) -> Result<(), ProjectError> {
        if self.map_path.is_none() {
            return Err(ProjectError::BuildArteryConfiguration(
                "Map path is missing".to_string(),
            ));
        }
        ArteryConfigurationBuilder::new(self.artery_path.to_owned())
            .project_name(self.project_name.to_owned())
            .map_path(self.map_path.to_owned().unwrap())
            .build()
            .map_err(|e| ProjectError::BuildArteryConfiguration(e.to_string()))?;

        Ok(())
    }
}
