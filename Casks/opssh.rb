cask "opssh" do
  arch arm: "arm64", intel: "amd64"

  version "0.1.0"

  on_macos do
    sha256 arm:   "a3215cc2e750dad178a03e5d6f334acac5ffc228f7cddce7581700c2fe24d323",
           intel: "648cf0cae27d1db567ef9ef149bdc1bb75a7957763270e0c685cdd9be75806cc"

    url "https://github.com/vlyl/opssh/releases/download/v#{version}/opssh_#{version}_darwin_#{arch}.tar.gz",
        verified: "github.com/vlyl/opssh/"
  end
  on_linux do
    sha256 arm:   "853c620b9754eeccce745b161dd80b1c116a66a462fe569209ce99eff9869f49",
           intel: "e0d2175517ba9f70901ae4bb57d548ff3e316a25503d71ec473f66cc27d18136"

    url "https://github.com/vlyl/opssh/releases/download/v#{version}/opssh_#{version}_linux_#{arch}.tar.gz",
        verified: "github.com/vlyl/opssh/"
  end

  name "opssh"
  desc "Manage OpenSSH hosts backed by the 1Password SSH Agent"
  homepage "https://github.com/vlyl/opssh"

  livecheck do
    url :url
    strategy :github_latest
  end

  binary "opssh"
end
