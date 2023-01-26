# frozen_string_literal: true

require_relative "lib/omniauth/social/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-social"
  spec.version = Omniauth::Social::VERSION
  spec.authors = ["ritaamritkar1212"]
  spec.email = ["rita.amritkar@gmail.com"]

  spec.summary = "One Gem whch will include all required omniauth stratergies"
  spec.description = "One Gem whch will include all required omniauth stratergies"
  spec.homepage = "https://github.com/izea/omniauth-social"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  # spec.metadata["source_code_uri"] = "https://github.com/izea/omniauth-social"
  # spec.metadata["changelog_uri"] = "TODO: Put your gem's CHANGELOG.md URL here."

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # spec.add_runtime_dependency 'jwt', '>= 2.0'
  spec.add_runtime_dependency 'omniauth', '>= 2.0', '< 3'
  spec.add_runtime_dependency 'omniauth-oauth2', '~> 1.8.0'
  spec.add_dependency 'omniauth-oauth', '~> 1.1'

  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'mocha'
  spec.add_development_dependency 'rake'

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
