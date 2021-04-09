Pod::Spec.new do |spec|

  spec.name         = "BitcoinSigner"
  spec.version      = "0.0.1"
  spec.summary      = "BitcoinSigner."


  spec.description  = <<-DESC
  BitcoinSigner
                   DESC

  spec.homepage     = "https://github.com/Bytom/Bycoin.iOS"
  spec.license      = "MIT"


  spec.author       = { "cezres" => "cezr@sina.com" }


  spec.swift_version = '5'
  spec.module_name  = 'BitcoinSigner'
  spec.platform     = :ios, "10.0"


  spec.source       = { :git => "https://github.com/Bytom/Bycoin.iOS.git", :tag => "#{spec.version}" }
  spec.source_files = "BitcoinSigner/**/*.{h,swift}"


  spec.resources = "BitcoinSigner/**/*.strings"


  spec.dependency "CryptoSwift"
  spec.dependency "secp256k1.swift"
  spec.dependency "ripemd160.swift"

end
