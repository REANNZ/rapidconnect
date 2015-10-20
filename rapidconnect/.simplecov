require 'codeclimate-test-reporter'

CodeClimate::TestReporter.configure do |config|
  config.path_prefix = 'rapidconnect'
  config.git_dir = '../'
end

CodeClimate::TestReporter.start

SimpleCov.start do
  add_filter('spec')
end
