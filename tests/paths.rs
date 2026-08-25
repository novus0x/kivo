use std::path::PathBuf;

use kivo::utils::paths::KivoPaths;

#[test]
fn default_path_uses_home_kivo() {
    let paths = KivoPaths::resolve(None).unwrap();
    assert!(paths.data_dir.ends_with(".kivo"));
    assert!(paths.database.file_name().unwrap() == "kivo.db");
    assert!(paths.database.parent().unwrap() == paths.data_dir);
}

#[test]
fn custom_data_dir() {
    let paths = KivoPaths::resolve(Some(PathBuf::from("/tmp/kivo-test"))).unwrap();
    assert_eq!(paths.data_dir, PathBuf::from("/tmp/kivo-test"));
    assert_eq!(paths.database, PathBuf::from("/tmp/kivo-test/kivo.db"));
}

#[test]
fn custom_dirs_are_independent() {
    let a = KivoPaths::resolve(Some(PathBuf::from("/tmp/kivo-a-test"))).unwrap();
    let b = KivoPaths::resolve(Some(PathBuf::from("/tmp/kivo-b-test"))).unwrap();
    assert_ne!(a.data_dir, b.data_dir);
    assert_ne!(a.database, b.database);
}
