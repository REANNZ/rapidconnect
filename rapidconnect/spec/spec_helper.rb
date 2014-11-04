require 'simplecov'

ENV['RACK_ENV'] = 'test'

require 'bundler'
Bundler.require :default, :test

require 'rack/test'

Webrat.configure do |config|
  config.mode = :rack
end

Mail.defaults do
  delivery_method :test
end

Sinatra::Base.set :app_root,
                  File.expand_path(File.join(File.dirname(__FILE__), '..'))

Sinatra::Base.set :app_logfile,
                  File.join(settings.app_root, 'logs', 'app-test.log')

Sinatra::Base.set :audit_logfile,
                  File.join(settings.app_root, 'logs', 'audit-test.log')

Sinatra::Base.set :issuer, 'https://rapid.example.org'
Sinatra::Base.set :hostname, 'rapid.example.org'
Sinatra::Base.set :organisations, '/tmp/rspec_organisations.json'
Sinatra::Base.set :federation, 'production'
Sinatra::Base.set :mail, from: 'noreply@example.org', to: 'support@example.org'

Sinatra::Base.set :export, enabled: true
Sinatra::Base.set :export, secret: 'test_secret'

legacy_rspec_matchers = [
  Webrat::Matchers::HasContent,
  Mail::Matchers::HasSentEmailMatcher
]

legacy_rspec_matchers.each do |m|
  m.instance_eval do
    alias_method :failure_message_when_negated, :negative_failure_message
  end
end

# Supply common framework actions to tests
module AppHelper
  def app
    RapidConnect
  end

  def session
    last_request.env['rack.session']
  end

  def last_email
    Mail::TestMailer.deliveries[0]
  end

  def flush_stores
    @redis.flushall
    Mail::TestMailer.deliveries.clear
  end

  def flash
    last_request.env['x-rack.flash']
  end
end

FactoryGirl.find_definitions

Timecop.safe_mode = true

RSpec.configure do |config|
  config.before { Redis::Connection::Memory.reset_all_databases }

  config.filter_run focus: true
  config.run_all_when_everything_filtered = true

  config.order = :random
  Kernel.srand config.seed

  config.include Rack::Test::Methods
  config.include Webrat::Methods
  config.include Webrat::Matchers
  config.include Mail::Matchers
  config.include AppHelper
  config.include FactoryGirl::Syntax::Methods
end
