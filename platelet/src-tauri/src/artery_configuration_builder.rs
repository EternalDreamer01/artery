use std::{
    collections::HashMap,
    fs::{self, create_dir, File},
    io::Write,
    process::{Command, ExitStatus},
};

use strfmt::strfmt;

use crate::misc::folder_exist;

#[derive(Default)]
pub struct ArteryConfigurationBuilder {
    artery_path: String,
    project_name: String,
    map_path: String,
    trips_number: u64,
}

impl ArteryConfigurationBuilder {
    pub fn new(artery_path: String) -> ArteryConfigurationBuilder {
        ArteryConfigurationBuilder {
            artery_path,
            trips_number: 10,
            ..Default::default()
        }
    }

    pub fn project_name(mut self, project_name: String) -> Self {
        self.project_name = project_name;
        self
    }

    pub fn map_path(mut self, map_path: String) -> Self {
        self.map_path = map_path;
        self
    }

    fn build_net(osmfile_path: &str, netfile_path: &str) -> Result<ExitStatus, String> {
        Ok(Command::new("netconvert")
            .args([
                "--osm-files",
                osmfile_path,
                "--output-file",
                netfile_path,
                "--geometry.remove",
                "--roundabouts.guess",
                "--ramps.guess",
                "--junctions.join",
                "--tls.guess-signals",
                "--tls.discard-simple",
                "--tls.join",
            ])
            .spawn()
            .map_err(|e| format!("Can't spawn net building command: {}", e))?
            .wait()
            .map_err(|e| format!("Can't wait for net building command to end: {}", e))?)
    }

    fn build_trips(
        netfile_path: &str,
        tripsfile_path: &str,
        trips_number: u64,
    ) -> Result<ExitStatus, String> {
        Ok(Command::new("python3")
            .args([
                "/usr/local/share/sumo/tools/randomTrips.py",
                "-n",
                netfile_path,
                "-e",
                &trips_number.to_string(),
                "-o",
                tripsfile_path,
            ])
            .spawn()
            .map_err(|e| format!("Can't spawn trips building command: {}", e))?
            .wait()
            .map_err(|e| format!("Can't wait for trips building command to end: {}", e))?)
    }

    fn build_routes(
        netfile_path: &str,
        tripsfile_path: &str,
        routefile_path: &str,
    ) -> Result<ExitStatus, String> {
        Ok(Command::new("duarouter")
            .args([
                "-n",
                netfile_path,
                "--route-files",
                tripsfile_path,
                "-o",
                routefile_path,
                "--ignore-errors",
            ])
            .spawn()
            .map_err(|e| format!("Can't spawn trips building command: {}", e))?
            .wait()
            .map_err(|e| format!("Can't wait for trips building command to end: {}", e))?)
    }

    fn build_sumo_config_files(&self, scenario_path: String) -> Result<(), String> {
        let netfile_path = format!("{}/{}.net.xml", scenario_path, self.project_name);
        let tripsfile_path = format!("{}/{}.trips.xml", scenario_path, self.project_name);
        let routefile_path = format!("{}/{}.rou.xml", scenario_path, self.project_name);

        /* TODO: Check programs status code */
        Self::build_net(&self.map_path, &netfile_path)?;
        Self::build_trips(&netfile_path, &tripsfile_path, self.trips_number)?;
        Self::build_routes(&netfile_path, &tripsfile_path, &routefile_path)?;

        let sumocfg_path = format!("{}/{}.sumocfg", scenario_path, self.project_name);

        let config_template = fs::read_to_string("./assets/base.sumocfg")
            .map_err(|e| format!("Can't read base config file: {}", e))?;

        let replace_vars = HashMap::from([
            ("netfile".to_string(), netfile_path.as_str()),
            ("routefile".to_string(), &routefile_path.as_str()),
        ]);

        let custom_config = strfmt(&config_template, &replace_vars)
            .map_err(|e| format!("Can't update config template : {}", e))?;

        let mut f = File::create(sumocfg_path).map_err(|e| e.to_string())?;

        f.write_all(custom_config.as_bytes())
            .map_err(|e| e.to_string())?;
        println!("{}", custom_config);

        Ok(())
    }

    fn build_omnet_config_file(&self, scenario_path: String) -> Result<(), String> {
        /* TODO: add more flexibility to this system */
        fs::copy("./assets/vehicles.xml", scenario_path.to_owned()).map_err(|e| e.to_string())?;
        fs::copy("./assets/services.xml", scenario_path.to_owned()).map_err(|e| e.to_string())?;
        fs::copy("./assets/omnetpp.ini", scenario_path.to_owned()).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn build(self) -> Result<(), String> {
        let scenario_path = format!("{}/scenarios/{}", self.artery_path, self.project_name);

        if !folder_exist(&scenario_path) {
            create_dir(scenario_path.to_owned())
                .map_err(|e| format!("Can't create build directory at {}: {}", scenario_path, e))?;
        }

        self.build_sumo_config_files(scenario_path.to_owned())?;
        self.build_omnet_config_file(scenario_path)?;
        Ok(())
    }
}
