// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{env::set_current_dir, path::Path, process::Command};

use artery_configuration_builder::ArteryConfigurationBuilder;
use misc::{create_folder_if_not_exist, create_menu_bar, create_menu_even_listener};
use once_cell::sync::OnceCell;
use project::Project;

mod artery_configuration_builder;
mod misc;
mod project;
mod security_configuration;

static LOADED_PROJECT: OnceCell<Project> = OnceCell::new();

#[tauri::command]
fn compile_artery() -> Result<(), String> {
    set_current_dir("..").map_err(|e| format!("Can't change directory to ../: {}", e))?;

    let build_path = Path::new("./build");

    create_folder_if_not_exist(build_path)
        .map_err(|e| format!("Can't create build directory: {}", e))?;

    set_current_dir(build_path).map_err(|e| format!("Can't change directory to ./build: {}", e))?;

    Command::new("cmake")
        .args(["../.."])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    Command::new("cmake")
        .args(["--build", ".", "--target", "run_epita-simulation", "-j7"])
        .spawn()
        .unwrap();

    Ok(())
}

#[tauri::command]
fn build_config() {
    if let Some(project) = LOADED_PROJECT.get() {
        let config_builder = ArteryConfigurationBuilder::new(project.artery_path.to_owned())
            .map_path(project.map_path.to_owned().unwrap())
            .project_name(project.project_name.to_owned());

        config_builder.build().unwrap();
    } else {
        println!("Can't build project")
    }
}

#[tauri::command]
fn create_new_project(
    window: tauri::Window,
    project_name: &str,
    artery_path: &str,
) -> Result<(), String> {
    println!("Creating new project");
    Project::new(project_name.to_string(), artery_path.to_string())
        .save_project_settings()
        .unwrap();
    window.close().unwrap();
    Ok(())
}

#[tauri::command]
async fn get_loaded_project() -> Option<Project> {
    LOADED_PROJECT.get().cloned()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            compile_artery,
            build_config,
            create_new_project,
            get_loaded_project
        ])
        .menu(create_menu_bar())
        .on_menu_event(create_menu_even_listener())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
