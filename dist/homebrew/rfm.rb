# Copy this into your tap at: homebrew-tools/Formula/rfm.rb
# (create the Formula/ directory — the tap currently only has Casks/)
#
# Before it will install, fill in the three TODOs below:
#   1. Confirm `homepage`/`url` point at the real repo.
#   2. Cut a git tag + GitHub release (e.g. v0.1.0) so the tarball URL exists.
#   3. Set `sha256` to the tarball hash:
#        curl -sL <the url below> | shasum -a 256
class Rfm < Formula
  desc "Encrypted, client-side S3 file mirror CLI and daemon"
  homepage "https://github.com/senecal-jjs/rust-file-mirror" # TODO: confirm
  url "https://github.com/senecal-jjs/rust-file-mirror/archive/refs/tags/v0.1.0.tar.gz" # TODO: confirm tag
  sha256 "REPLACE_WITH_TARBALL_SHA256" # TODO: shasum -a 256 of the tarball above
  license "MIT" # TODO: confirm license
  head "https://github.com/senecal-jjs/rust-file-mirror.git", branch: "main"

  depends_on "rust" => :build
  # aws-sdk-s3 -> aws-lc-sys compiles C and needs CMake. If a build ever fails on
  # x86_64 with an assembler error, add `depends_on "nasm" => :build` too.
  depends_on "cmake" => :build

  def install
    # `rfm` lives in a workspace member, so aim --path at that crate rather than
    # the workspace root (which `std_cargo_args` would default to).
    system "cargo", "install", *std_cargo_args(path: "crates/mirror-cli")
  end

  service do
    run [opt_bin/"rfm", "watch"]
    keep_alive true
    working_dir Dir.home
    log_path var/"log/rfm.log"
    error_log_path var/"log/rfm.log"
    # `brew services` (launchd) does NOT inherit your shell env. Point the AWS SDK
    # at a credentials profile instead of baking secret keys into a public formula.
    environment_variables AWS_PROFILE: "rfm", RFM_LOG: "info"
  end

  def caveats
    <<~EOS
      rfm needs a config, S3 credentials, and an unlocked vault before it runs:

        1. Create a config (default: rfm.toml, or ~/.config/rfm/config.toml).
        2. Provide S3 credentials — an AWS profile is recommended:
             add an [rfm] section to ~/.aws/credentials, then use AWS_PROFILE=rfm
        3. Initialize and unlock the vault:
             rfm init
             rfm unlock

      Run the daemon in the foreground:
             rfm watch
      or under launchd:
             brew services start rfm

      WARNING: there is no recovery if the vault passphrase is lost.
    EOS
  end

  test do
    assert_match "rfm", shell_output("#{bin}/rfm --help")
  end
end
