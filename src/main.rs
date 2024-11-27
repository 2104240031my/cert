mod crypto;
mod net;
mod test_script;

use ::crypto::cmd;
use ::crypto::test;

const VERSION: &str = "0.0.4";

fn main() {

    test_script::main();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println_cmd_usage();
        return;
    }

    let cmd: fn (args: Vec<String>) = match args[1].as_str() {
        "version"  => |_: Vec<String>| { println!("crypto-v{}", VERSION) },
        "encrypt"  => cmd::cmd_encrypt::cmd_main,
        "decrypt"  => cmd::cmd_decrypt::cmd_main,
        "seal"     => cmd::cmd_seal::cmd_main,
        "open"     => cmd::cmd_open::cmd_main,
        "hash"     => cmd::cmd_hash::cmd_main,
        "xof"      => cmd::cmd_xof::cmd_main,
        "mac"      => cmd::cmd_mac::cmd_main,
        "pubkey"   => cmd::cmd_pubkey::cmd_main,
        "keyshare" => cmd::cmd_keyshare::cmd_main,
        "sign"     => cmd::cmd_sign::cmd_main,
        "verify"   => cmd::cmd_verify::cmd_main,
        "help"     => |_: Vec<String>| { println_cmd_usage(); },
        #[cfg(debug_assertions)]
        "test"     => |_: Vec<String>| { test::test(); },
        _          => |_: Vec<String>| { println!("[!Err]: there is no such sub-command."); }
    };

    cmd((&args[1..]).to_vec());

}

fn println_cmd_usage() {
    println!("crypto command usage:");
    println!("    crypto [sub-command] ...");
    println!("");
    println!("available sub-commands are listed below:");
    println!(" - version");
    println!(" - encrypt");
    println!(" - decrypt");
    println!(" - seal");
    println!(" - open");
    println!(" - hash");
    println!(" - xof");
    println!(" - mac");
    println!(" - pubkey");
    println!(" - keyshare");
    println!(" - sign");
    println!(" - verify");
    println!(" - help");
}