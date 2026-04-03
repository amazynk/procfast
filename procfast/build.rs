use libbpf_cargo::SkeletonBuilder;
use std::path::{Path, PathBuf};
use std::{env, fs};

const BPF_PROGRAMS: &[&str] = &["cpu", "mem", "net", "disk", "thermal", "irq", "proc", "fd", "sock", "cgroup"];

fn main() {
    let bpf_src = Path::new("../procfast-bpf/src");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let skel_dir = out_dir.join("skel");
    fs::create_dir_all(&skel_dir).unwrap();

    for prog in BPF_PROGRAMS {
        let src = bpf_src.join(format!("{prog}.bpf.c"));
        let out = skel_dir.join(format!("{prog}.skel.rs"));

        SkeletonBuilder::new()
            .source(&src)
            .clang_args([
                format!("-I{}", bpf_src.display()),
                "-Wno-compare-distinct-pointer-types".to_string(),
            ])
            .build_and_generate(&out)
            .unwrap_or_else(|e| panic!("failed to build {prog}.bpf.c: {e}"));

        // Workaround: libbpf-cargo generates duplicate enum discriminants
        // for BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED and
        // BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED (both share values
        // with their non-DEPRECATED counterparts). Remove the _DEPRECATED lines.
        fix_duplicate_discriminants(&out);

        println!("cargo:rerun-if-changed={}", src.display());
    }

    println!("cargo:rerun-if-changed={}", bpf_src.join("procfast.h").display());
}

fn fix_duplicate_discriminants(path: &Path) {
    let content = fs::read_to_string(path).unwrap();
    if !content.contains("_DEPRECATED") {
        return;
    }
    let fixed: String = content
        .lines()
        .filter(|line| !line.contains("_DEPRECATED"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, fixed).unwrap();
}
