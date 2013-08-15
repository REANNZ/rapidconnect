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

Sinatra::Base.set :app_root, File.expand_path(File.join(File.dirname(__FILE__), '..'))
Sinatra::Base.set :app_logfile, File.join(settings.app_root,'logs','app-test.log')
Sinatra::Base.set :audit_logfile, File.join(settings.app_root, 'logs', 'audit-test.log')
Sinatra::Base.set :mail, {from:'noreply@example.org', to:'support@example.org'}

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
end

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.include Webrat::Methods
  config.include Webrat::Matchers
  config.include Mail::Matchers
  config.include AppHelper
end
