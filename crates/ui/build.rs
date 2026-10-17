fn main() {
    // Track additions and changes anywhere in the embedded directory tree.
    println!("cargo:rerun-if-changed=assets");
}
