use std::{
    fs::{self, create_dir},
    path::Path,
};

use tauri::{
    api::dialog::FileDialogBuilder, CustomMenuItem, Manager, Menu, Submenu, WindowBuilder,
    WindowMenuEvent,
};

use crate::{project::Project, LOADED_PROJECT};

pub fn folder_exist<P: AsRef<Path>>(path: P) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

pub fn create_folder_if_not_exist<P: AsRef<Path>>(path: P) -> Result<(), std::io::Error> {
    if !folder_exist(&path) {
        return create_dir(&path);
    }
    Ok(())
}

pub fn create_menu_bar() -> Menu {
    let new = CustomMenuItem::new("new_project".to_string(), "New Project");
    let save = CustomMenuItem::new("save_project".to_string(), "Save Project");
    let load = CustomMenuItem::new("load_project".to_string(), "Load Project");
    let submenu = Submenu::new(
        "File",
        Menu::new().add_item(new).add_item(save).add_item(load),
    );
    Menu::new().add_submenu(submenu)
}

pub fn create_menu_even_listener() -> impl Fn(WindowMenuEvent) + Send + Sync + 'static {
    |event: WindowMenuEvent| {
        match event.menu_item_id() {
            "load_project" => FileDialogBuilder::new()
                .add_filter("Platelet configuration file .platelet", &["platelet"])
                .pick_file(|folder_path| {
                    // do something with the optional folder path here
                    // the folder path is `None` if the user closed the dialog
                    match folder_path {
                        Some(path) => LOADED_PROJECT
                            .set(
                                Project::load_project_settings(path.to_str().unwrap().to_owned())
                                    .unwrap(),
                            )
                            .unwrap(),
                        None => (),
                    };
                }),
            "new_project" => {
                WindowBuilder::new(
                    &event.window().app_handle(),
                    "new_project",
                    tauri::WindowUrl::App("newProject".into()),
                )
                .build()
                .unwrap();
            }
            _ => {}
        };
    }
}
