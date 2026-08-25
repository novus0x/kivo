use std::path::PathBuf;

pub struct KivoPaths {
    pub data_dir: PathBuf,
    pub database: PathBuf,
}

impl KivoPaths {
    pub fn resolve(data_dir: Option<PathBuf>) -> Result<Self, String> {
        let data_dir = match data_dir {
            Some(dir) => dir,
            None => {
                let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
                home.join(".kivo")
            }
        };

        let database = data_dir.join("kivo.db");
        Ok(KivoPaths { data_dir, database })
    }
}
