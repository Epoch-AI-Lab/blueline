# Homebrew formula for blueline. Source build: the release binaries are
# attested separately (see .github/workflows/release.yml); this formula
# compiles from the signed tag with the pinned toolchain.
class Blueline < Formula
  desc "Release-diff review desk for the package install line"
  homepage "https://github.com/Epoch-AI-Lab/blueline"
  url "https://github.com/Epoch-AI-Lab/blueline/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "FILL_AT_RELEASE" # sha256 of the tag tarball; filled by the release process
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "."
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/blueline --version")
  end
end
